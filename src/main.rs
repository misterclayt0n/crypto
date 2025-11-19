use std::{
    cmp::Ordering,
    fs,
    io::{self, Read},
    path::PathBuf,
    thread,
    time::Duration,
};

use clap::Parser;
use color_eyre::eyre::{Result, WrapErr, bail, ensure, eyre};
use reqwest::{blocking::Client, StatusCode};
use serde::{Deserialize, Serialize};
use rand::Rng;

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();
    let ciphertext = args.read_input()?;

    let letter_freqs = parse_letter_freq_table()?;
    let solver = Solver::new(args.steps, args.restarts, letter_freqs);
    let result = solver.solve(&ciphertext)?;

    println!("{}", result.plaintext);
    println!("\nSubstitution table (cipher -> plain):");
    for (index, &plain_idx) in result.mapping.iter().enumerate() {
        let cipher = (b'A' + index as u8) as char;
        let plain = (b'A' + plain_idx as u8) as char;
        println!("{cipher} -> {plain}");
    }

    let refinement = refine_with_llm(&result.plaintext)?;
    println!("\nLLM response:\n{refinement}");

    Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Monoalphabetic substitution cipher solver")]
struct Args {
    /// Optional path to a file that contains the ciphertext
    #[arg(short, long)]
    file: Option<PathBuf>,

    /// Ciphertext passed directly on the command line
    text: Option<String>,

    /// Number of hill-climbing steps to perform per restart
    #[arg(short, long, default_value_t = 25_000)]
    steps: usize,

    /// Number of times to restart the search with a different key guess
    #[arg(short, long, default_value_t = 30)]
    restarts: usize,
}

impl Args {
    fn read_input(&self) -> Result<String> {
        if let Some(path) = &self.file {
            return fs::read_to_string(path).wrap_err_with(|| format!("failed to read {:?}", path));
        }

        if let Some(text) = &self.text {
            return Ok(text.clone());
        }

        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .wrap_err("failed to read ciphertext from stdin")?;
        Ok(buffer)
    }
}

struct Solver {
    steps: usize,
    restarts: usize,
    model: ScoreModel,
    plain_order: [usize; 26],
}

impl Solver {
    fn new(steps: usize, restarts: usize, letter_freqs: [f64; 26]) -> Self {
        let plain_order = english_frequency_order(&letter_freqs);
        Self {
            steps,
            restarts,
            model: ScoreModel::new(&letter_freqs),
            plain_order,
        }
    }

    fn solve(&self, ciphertext: &str) -> Result<SolverResult> {
        let prepared = PreparedText::from(ciphertext);
        ensure!(
            !prepared.letters.is_empty(),
            "ciphertext must contain at least one alphabetic character"
        );

        let base_key = frequency_key(&prepared.letters, &self.plain_order);
        let mut rng = rand::thread_rng();
        let mut best_overall: Option<SolverResult> = None;

        for restart in 0..self.restarts {
            let mut key = if restart == 0 {
                base_key
            } else {
                randomize_key(&base_key, &mut rng, 10 + restart)
            };

            let mut plain_letters = decrypt_letters(&prepared.letters, &key);
            let mut score = self.model.score(&plain_letters);
            let mut best_restart_key = key;
            let mut best_restart_score = score;

            for step in 0..self.steps {
                let a = rng.gen_range(0..26);
                let mut b = rng.gen_range(0..26);
                while b == a {
                    b = rng.gen_range(0..26);
                }
                key.swap(a, b);

                let candidate_letters = decrypt_letters(&prepared.letters, &key);
                let candidate_score = self.model.score(&candidate_letters);
                let temp = self.temperature(step);
                let delta = candidate_score - score;
                let accept = delta > 0.0 || rng.r#gen::<f64>() < (delta / temp).exp();

                if accept {
                    plain_letters = candidate_letters;
                    score = candidate_score;
                } else {
                    key.swap(a, b);
                }

                if score > best_restart_score {
                    best_restart_score = score;
                    best_restart_key = key;
                }
            }

            let plaintext = prepared.render(&best_restart_key);
            let restart_result = SolverResult {
                plaintext,
                mapping: best_restart_key,
                score: best_restart_score,
            };

            match &mut best_overall {
                Some(current) if current.score >= restart_result.score => {}
                Some(current) => *current = restart_result,
                None => best_overall = Some(restart_result),
            }
        }

        best_overall.ok_or_else(|| eyre!("failed to produce a key candidate"))
    }

    fn temperature(&self, step: usize) -> f64 {
        let steps = self.steps.max(1);
        let progress = step as f64 / steps as f64;
        ((1.0 - progress).max(0.01)) * 10.0
    }
}

struct SolverResult {
    plaintext: String,
    mapping: [usize; 26],
    score: f64,
}

struct PreparedText {
    tokens: Vec<Token>,
    letters: Vec<usize>,
}

impl PreparedText {
    fn from(input: &str) -> Self {
        let mut tokens = Vec::with_capacity(input.len());
        let mut letters = Vec::new();

        for ch in input.chars() {
            if ch.is_ascii_alphabetic() {
                let upper = ch.is_ascii_uppercase();
                let idx = (ch.to_ascii_uppercase() as u8 - b'A') as usize;
                tokens.push(Token::Letter {
                    idx,
                    is_upper: upper,
                });
                letters.push(idx);
            } else {
                tokens.push(Token::Other(ch));
            }
        }

        Self { tokens, letters }
    }

    fn render(&self, key: &[usize; 26]) -> String {
        let mut output = String::with_capacity(self.tokens.len());
        for token in &self.tokens {
            match *token {
                Token::Letter { idx, is_upper } => {
                    let mapped = key[idx];
                    let ch = (b'a' + mapped as u8) as char;
                    if is_upper {
                        output.push(ch.to_ascii_uppercase());
                    } else {
                        output.push(ch);
                    }
                }
                Token::Other(ch) => output.push(ch),
            }
        }
        output
    }
}

#[derive(Copy, Clone)]
enum Token {
    Letter { idx: usize, is_upper: bool },
    Other(char),
}

fn decrypt_letters(cipher_letters: &[usize], key: &[usize; 26]) -> Vec<usize> {
    cipher_letters.iter().map(|&idx| key[idx]).collect()
}

fn frequency_key(cipher_letters: &[usize], plain_order: &[usize; 26]) -> [usize; 26] {
    let mut counts = [0usize; 26];
    for &idx in cipher_letters {
        counts[idx] += 1;
    }

    let mut letters: Vec<usize> = (0..26).collect();
    letters.sort_by(|&a, &b| counts[b].cmp(&counts[a]));

    let mut key = [0usize; 26];
    for (cipher_idx, plain_idx) in letters.iter().zip(plain_order.iter()) {
        key[*cipher_idx] = *plain_idx;
    }
    key
}

fn randomize_key(base: &[usize; 26], rng: &mut impl Rng, swaps: usize) -> [usize; 26] {
    let mut key = *base;
    for _ in 0..swaps {
        let a = rng.gen_range(0..26);
        let mut b = rng.gen_range(0..26);
        while a == b {
            b = rng.gen_range(0..26);
        }
        key.swap(a, b);
    }
    key
}

fn english_frequency_order(letter_freqs: &[f64; 26]) -> [usize; 26] {
    let mut letters: Vec<usize> = (0..26).collect();
    letters.sort_by(|&a, &b| {
        letter_freqs[b]
            .partial_cmp(&letter_freqs[a])
            .unwrap_or(Ordering::Equal)
    });

    let mut order = [0usize; 26];
    for (pos, idx) in letters.iter().enumerate() {
        order[pos] = *idx;
    }
    order
}

struct ScoreModel {
    letter_log_probs: [f64; 26],
    bigram_log_probs: [[f64; 26]; 26],        // ADD THIS
    trigram_log_probs: [[[f64; 26]; 26]; 26], // ADD THIS
}

impl ScoreModel {
    fn new(letter_freqs: &[f64; 26]) -> Self {
        let letter_total: f64 = letter_freqs.iter().sum();
        let letter_floor = (1.0 / (letter_total * 1000.0)).ln();
        let mut letter_log_probs = [0.0; 26];
        for (i, freq) in letter_freqs.iter().enumerate() {
            letter_log_probs[i] = if *freq > 0.0 {
                (freq / letter_total).ln()
            } else {
                letter_floor
            };
        }

        let bigram_total: f64 = BIGRAM_FREQ.iter().map(|(_, freq)| freq).sum();
        let bigram_floor = (1.0 / (bigram_total * 10_000.0)).ln();
        let mut bigram_log_probs = [[bigram_floor; 26]; 26];
        for &(pair, freq) in BIGRAM_FREQ {
            let bytes = pair.as_bytes();
            let a = (bytes[0] - b'A') as usize;
            let b = (bytes[1] - b'A') as usize;
            bigram_log_probs[a][b] = (freq / bigram_total).ln();
        }

        let trigram_total: f64 = TRIGRAM_FREQ.iter().map(|(_, freq)| freq).sum();
        let trigram_floor = (1.0 / (trigram_total * 100_000.0)).ln();
        let mut trigram_log_probs = [[[trigram_floor; 26]; 26]; 26];
        for &(tri, freq) in TRIGRAM_FREQ {
            let bytes = tri.as_bytes();
            let a = (bytes[0] - b'A') as usize;
            let b = (bytes[1] - b'A') as usize;
            let c = (bytes[2] - b'A') as usize;
            trigram_log_probs[a][b][c] = (freq / trigram_total).ln();
        }

        Self {
            letter_log_probs,
            bigram_log_probs,
            trigram_log_probs,
        }
    }

    fn score(&self, letters: &[usize]) -> f64 {
        if letters.is_empty() {
            return f64::NEG_INFINITY;
        }

        let mut total = 0.0;
        for &idx in letters {
            total += self.letter_log_probs[idx];
        }

        for window in letters.windows(2) {
            total += self.bigram_log_probs[window[0]][window[1]];
        }

        // 3. Trigrams (The connection between 3 letters)
        for window in letters.windows(3) {
            total += self.trigram_log_probs[window[0]][window[1]][window[2]];
        }

        total
    }
}

const GEMINI_URL: &str = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent";

fn refine_with_llm(prompt: &str) -> Result<String> {
    let api_key = std::env::var("GEMINI_API_KEY")
        .wrap_err("GEMINI_API_KEY environment variable must be set to call Gemini API")?;

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .wrap_err("failed to construct HTTP client")?;

    let request = LlmRequest {
        contents: vec![LlmContent {
            parts: vec![LlmPart {
                text: prompt.to_string(),
            }],
        }],
    };

    let mut delay = Duration::from_secs(1);
    let max_attempts = 3;
    let mut last_error = None;

    for attempt in 0..max_attempts {
        let response = client
            .post(GEMINI_URL)
            .header("X-goog-api-key", &api_key)
            .json(&request)
            .send()
            .wrap_err("failed to contact Gemini API")?;

        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            let body = response.text().unwrap_or_default();
            last_error = Some(eyre!("Gemini API rate limited request: {body}"));
            if attempt + 1 == max_attempts {
                break;
            }
            thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_secs(8));
            continue;
        }

        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            return Err(eyre!("Gemini API returned status {status}: {body}"));
        }

        let response: LlmResponse = response
            .json()
            .wrap_err("failed to parse response from Gemini API")?;

        return response
            .candidates
            .and_then(|candidates| {
                candidates.into_iter().find_map(|candidate| {
                    candidate.content.and_then(|content| {
                        content
                            .parts
                            .into_iter()
                            .find_map(|part| part.text)
                    })
                })
            })
            .ok_or_else(|| eyre!("Gemini API response did not contain text"));
    }

    Err(last_error.unwrap_or_else(|| eyre!("failed to contact Gemini API")))
}

#[derive(Serialize)]
struct LlmRequest {
    contents: Vec<LlmContent>,
}

#[derive(Serialize)]
struct LlmContent {
    parts: Vec<LlmPart>,
}

#[derive(Serialize)]
struct LlmPart {
    text: String,
}

#[derive(Deserialize)]
struct LlmResponse {
    #[serde(default)]
    candidates: Option<Vec<LlmCandidate>>,
}

#[derive(Deserialize)]
struct LlmCandidate {
    content: Option<LlmContentResponse>,
}

#[derive(Deserialize)]
struct LlmContentResponse {
    #[serde(default)]
    parts: Vec<LlmPartResponse>,
}

#[derive(Deserialize)]
struct LlmPartResponse {
    text: Option<String>,
}

const LETTER_FREQ_TABLE: &str = include_str!("../frequency_table/table1.csv");

fn parse_letter_freq_table() -> Result<[f64; 26]> {
    let mut freqs = [0.0; 26];
    let mut seen = [false; 26];

    for (line_no, raw_line) in LETTER_FREQ_TABLE.lines().enumerate() {
        if line_no == 0 || raw_line.trim().is_empty() {
            continue;
        }

        let mut parts = raw_line.split(',');
        let letter_str = parts
            .next()
            .ok_or_else(|| eyre!("malformed frequency table: missing letter column"))?
            .trim();
        let freq_str = parts
            .next()
            .ok_or_else(|| eyre!("malformed frequency table: missing frequency column"))?
            .trim();

        ensure!(
            letter_str.len() == 1,
            "frequency table letter entries must be a single character"
        );
        let ch = letter_str.chars().next().unwrap();
        ensure!(
            ch.is_ascii_alphabetic(),
            "frequency table letter '{ch}' is not alphabetic"
        );
        let idx = (ch.to_ascii_uppercase() as u8 - b'A') as usize;
        ensure!(!seen[idx], "duplicate letter '{ch}' in frequency table");

        let freq: f64 = freq_str
            .parse()
            .wrap_err_with(|| format!("failed to parse frequency for '{ch}'"))?;
        freqs[idx] = freq;
        seen[idx] = true;
    }

    if seen.iter().any(|&flag| !flag) {
        bail!("frequency table is missing entries for one or more letters");
    }

    Ok(freqs)
}

const BIGRAM_FREQ: &[(&str, f64)] = &[
    ("TH", 2.71),
    ("HE", 2.33),
    ("IN", 2.03),
    ("ER", 1.78),
    ("AN", 1.61),
    ("RE", 1.41),
    ("ND", 1.32),
    ("ON", 1.32),
    ("EN", 1.20),
    ("AT", 1.17),
    ("OU", 1.16),
    ("ED", 1.15),
    ("HA", 1.11),
    ("TO", 1.09),
    ("OR", 1.06),
    ("IT", 1.03),
    ("IS", 1.00),
    ("HI", 0.98),
    ("ES", 0.97),
    ("NG", 0.95),
    ("ST", 0.92),
    ("TE", 0.90),
    ("AR", 0.88),
    ("NT", 0.87),
    ("TI", 0.86),
    ("EA", 0.85),
    ("LE", 0.83),
    ("OF", 0.81),
    ("AL", 0.80),
    ("DE", 0.79),
    ("AS", 0.76),
    ("SE", 0.73),
    ("SA", 0.72),
    ("ME", 0.71),
    ("RO", 0.70),
    ("VE", 0.69),
    ("RI", 0.68),
    ("OM", 0.67),
    ("IO", 0.65),
    ("IC", 0.64),
    ("NE", 0.63),
    ("RA", 0.62),
    ("CO", 0.61),
    ("TA", 0.60),
    ("CE", 0.59),
    ("LL", 0.58),
    ("SI", 0.57),
    ("RT", 0.56),
    ("UR", 0.55),
    ("LI", 0.54),
    ("CH", 0.53),
    ("MA", 0.52),
    ("PE", 0.51),
    ("AC", 0.50),
    ("NS", 0.49),
    ("IL", 0.48),
    ("US", 0.47),
    ("NC", 0.46),
    ("UT", 0.45),
    ("FO", 0.44),
    ("SS", 0.43),
    ("SO", 0.42),
    ("RS", 0.41),
    ("BE", 0.40),
    ("DI", 0.39),
    ("LA", 0.38),
    ("PR", 0.37),
    ("NO", 0.36),
    ("TR", 0.35),
    ("CA", 0.34),
    ("EL", 0.33),
    ("UN", 0.32),
    ("AM", 0.31),
    ("MP", 0.30),
    ("WA", 0.29),
    ("IV", 0.28),
    ("HO", 0.27),
    ("GE", 0.26),
    ("KE", 0.25),
    ("WI", 0.24),
    ("OW", 0.23),
    ("PA", 0.22),
    ("NA", 0.21),
    ("MI", 0.20),
    ("OL", 0.19),
    ("MO", 0.18),
    ("PO", 0.17),
    ("WE", 0.16),
    ("CT", 0.15),
    ("UL", 0.14),
    ("WH", 0.13),
    ("FF", 0.12),
    ("IR", 0.11),
    ("VI", 0.10),
    ("LY", 0.09),
    ("EE", 0.08),
];

const TRIGRAM_FREQ: &[(&str, f64)] = &[
    ("THE", 1.81),
    ("AND", 0.73),
    ("ING", 0.72),
    ("ENT", 0.42),
    ("ION", 0.42),
    ("HER", 0.36),
    ("FOR", 0.34),
    ("THA", 0.33),
    ("NTH", 0.33),
    ("INT", 0.32),
    ("ERE", 0.31),
    ("TIO", 0.31),
    ("TER", 0.30),
    ("EST", 0.28),
    ("ERS", 0.28),
    ("ATI", 0.26),
    ("HAT", 0.26),
    ("ATE", 0.25),
    ("ALL", 0.25),
    ("ETH", 0.24),
    ("HES", 0.24),
    ("VER", 0.24),
    ("HIS", 0.24),
    ("OFT", 0.22),
    ("ITH", 0.21),
    ("FTH", 0.21),
    ("STH", 0.21),
    ("OTH", 0.21),
    ("RES", 0.21),
    ("ONT", 0.20),
    ("DTH", 0.20),
    ("ARE", 0.20),
    ("SIN", 0.19),
    ("STO", 0.19),
    ("EAR", 0.19),
    ("ERE", 0.19),
    ("IVE", 0.18),
    ("WAS", 0.18),
    ("ECT", 0.18),
    ("COM", 0.18),
    ("MEN", 0.18),
    ("PRO", 0.17),
    ("TIC", 0.17),
    ("ICA", 0.17),
    ("DIS", 0.17),
    ("NCE", 0.17),
    ("ACT", 0.17),
    ("EVE", 0.17),
    ("OUS", 0.17),
    ("ITY", 0.17),
];
