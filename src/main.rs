use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fs,
    io::{self, Read},
    path::PathBuf,
};

use clap::Parser;
use color_eyre::eyre::{Result, WrapErr, bail, ensure, eyre};
use rand::Rng;

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();
    let ciphertext = args.read_input()?;

    let letter_freqs = parse_letter_freq_table()?;
    let dictionary = load_dictionary()?;
    let soundex_index = build_soundex_index(&dictionary);
    let solver = Solver::new(args.steps, args.restarts, letter_freqs, dictionary.clone(), soundex_index.clone());
    let result = solver.solve(&ciphertext)?;

    println!("{}", result.plaintext);
    println!("\nSubstitution table (cipher -> plain):");
    for (index, &plain_idx) in result.mapping.iter().enumerate() {
        let cipher = (b'A' + index as u8) as char;
        let plain = (b'A' + plain_idx as u8) as char;
        println!("{cipher} -> {plain}");
    }

    // Apply word segmentation and character corrections
    let segmented = segment_and_correct(&result.plaintext, &dictionary);
    println!("\nWord-segmented and corrected output:");
    println!("{}", segmented);

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
    #[arg(short, long, default_value_t = 30_000)]
    steps: usize,

    /// Number of times to restart the search with a different key guess
    #[arg(short, long, default_value_t = 50)]
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
    fn new(
        steps: usize,
        restarts: usize,
        letter_freqs: [f64; 26],
        dictionary: HashSet<String>,
        soundex_index: HashMap<String, Vec<String>>
    ) -> Self {
        let plain_order = english_frequency_order(&letter_freqs);
        Self {
            steps,
            restarts,
            model: ScoreModel::new(&letter_freqs, dictionary, soundex_index),
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

            // Use dictionary-based scoring for final evaluation
            let final_score = self.model.score_with_text(&plaintext);

            let restart_result = SolverResult {
                plaintext,
                mapping: best_restart_key,
                score: final_score,
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
    bigram_log_probs: [[f64; 26]; 26],
    trigram_log_probs: [[[f64; 26]; 26]; 26],
    dictionary: HashSet<String>,
    soundex_index: HashMap<String, Vec<String>>,
}

impl ScoreModel {
    fn new(letter_freqs: &[f64; 26], dictionary: HashSet<String>, soundex_index: HashMap<String, Vec<String>>) -> Self {
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
            dictionary,
            soundex_index,
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

        for window in letters.windows(3) {
            total += self.trigram_log_probs[window[0]][window[1]][window[2]];
        }

        total
    }

    fn score_with_text(&self, text: &str) -> f64 {
        let prepared = PreparedText::from(text);
        let mut base_score = self.score(&prepared.letters);

        // Add dictionary-based scoring with Soundex phonetic matching
        let words: Vec<String> = text
            .split(|c: char| !c.is_ascii_alphabetic())
            .filter(|w| w.len() >= 2)
            .map(|w| w.to_lowercase())
            .collect();

        let mut word_score = 0.0;
        let mut matched_words = 0;

        for word in &words {
            if self.dictionary.contains(word) {
                // Exact match - highest bonus
                word_score += (word.len() as f64) * 5.0;
                matched_words += 1;
            } else if word.len() >= 3 {
                // Try Soundex phonetic matching
                let soundex_code = soundex(word);
                if let Some(similar_words) = self.soundex_index.get(&soundex_code) {
                    if !similar_words.is_empty() {
                        // Phonetic match - partial bonus
                        word_score += (word.len() as f64) * 2.0;
                        matched_words += 1;
                    }
                }
            }
        }

        // Add word score weighted by match percentage
        if !words.is_empty() {
            let match_ratio = matched_words as f64 / words.len() as f64;
            base_score += word_score * match_ratio;
        }

        base_score
    }
}

fn soundex(word: &str) -> String {
    if word.is_empty() {
        return String::from("0000");
    }

    let chars: Vec<char> = word.to_uppercase().chars().collect();
    let mut code = String::new();

    // Keep the first letter
    code.push(chars[0]);

    let mut prev_code = get_soundex_code(chars[0]);

    for &ch in &chars[1..] {
        let curr_code = get_soundex_code(ch);
        if curr_code != '0' && curr_code != prev_code {
            code.push(curr_code);
            if code.len() == 4 {
                break;
            }
        }
        if curr_code != '0' {
            prev_code = curr_code;
        }
    }

    // Pad with zeros to length 4
    while code.len() < 4 {
        code.push('0');
    }

    code
}

fn get_soundex_code(ch: char) -> char {
    match ch {
        'B' | 'F' | 'P' | 'V' => '1',
        'C' | 'G' | 'J' | 'K' | 'Q' | 'S' | 'X' | 'Z' => '2',
        'D' | 'T' => '3',
        'L' => '4',
        'M' | 'N' => '5',
        'R' => '6',
        _ => '0',
    }
}

fn build_soundex_index(dictionary: &HashSet<String>) -> HashMap<String, Vec<String>> {
    let mut index: HashMap<String, Vec<String>> = HashMap::new();

    for word in dictionary {
        let code = soundex(word);
        index.entry(code).or_insert_with(Vec::new).push(word.clone());
    }

    index
}

fn segment_and_correct(text: &str, dictionary: &HashSet<String>) -> String {
    // STEP 1: Apply character-level corrections FIRST on the raw concatenated text
    let char_corrected = apply_character_corrections_to_raw(text, dictionary);

    // STEP 2: Now segment the corrected text into words
    let mut result = String::new();
    let mut current_segment = String::new();

    for ch in char_corrected.chars() {
        if ch.is_ascii_alphabetic() {
            current_segment.push(ch);
        } else {
            if !current_segment.is_empty() {
                let segmented = segment_words(&current_segment.to_lowercase(), dictionary);
                // Preserve capitalization of first letter
                if current_segment.chars().next().unwrap().is_uppercase() && !segmented.is_empty() {
                    let mut chars = segmented.chars();
                    result.push(chars.next().unwrap().to_ascii_uppercase());
                    result.push_str(&chars.collect::<String>());
                } else {
                    result.push_str(&segmented);
                }
                current_segment.clear();
            }
            result.push(ch);
        }
    }

    // Handle last segment
    if !current_segment.is_empty() {
        let segmented = segment_words(&current_segment.to_lowercase(), dictionary);
        if current_segment.chars().next().unwrap().is_uppercase() && !segmented.is_empty() {
            let mut chars = segmented.chars();
            result.push(chars.next().unwrap().to_ascii_uppercase());
            result.push_str(&chars.collect::<String>());
        } else {
            result.push_str(&segmented);
        }
    }

    // STEP 3: Final validation - only output dictionary words
    validate_all_words(&result, dictionary)
}

fn apply_character_corrections_to_raw(text: &str, dictionary: &HashSet<String>) -> String {
    let mut best_text = text.to_string();
    let mut best_score = score_raw_text(&best_text, dictionary);

    // Try systematic pair swaps on the RAW unsegmented text
    let swap_pairs = [
        ('m', 'b'),
        ('p', 'y'),
        ('v', 'p'),
        ('j', 'x'),
        ('y', 'v'),
        ('b', 'm'),
    ];

    // Try multiple passes of swaps
    for _ in 0..3 {
        let mut improved = false;

        for &(c1, c2) in &swap_pairs {
            let test_text = swap_chars(&best_text, c1, c2);
            let test_score = score_raw_text(&test_text, dictionary);

            if test_score > best_score {
                best_score = test_score;
                best_text = test_text;
                improved = true;
            }
        }

        if !improved {
            break;
        }
    }

    best_text
}

fn score_raw_text(text: &str, dictionary: &HashSet<String>) -> f64 {
    // Score by counting how many dictionary words can be found as substrings
    let lower = text.to_lowercase();
    let mut score = 0.0;

    // Check for all dictionary words as substrings
    for word in dictionary.iter() {
        if word.len() >= 4 {  // Only check longer words to avoid false positives
            let count = lower.matches(word.as_str()).count();
            if count > 0 {
                score += (word.len() as f64).powi(2) * count as f64;
            }
        }
    }

    score
}

fn validate_all_words(text: &str, dictionary: &HashSet<String>) -> String {
    // Common single/double letter words that might not be in dictionary
    let common_words: HashSet<&str> = [
        "a", "i", "to", "of", "in", "on", "at", "is", "it", "or", "as", "be",
    ].iter().cloned().collect();

    let words: Vec<&str> = text.split_whitespace()
        .filter(|word| {
            let clean = word.to_lowercase()
                .trim_matches(|c: char| !c.is_ascii_alphabetic())
                .to_string();
            if clean.is_empty() {
                return false;
            }
            // Only keep words that are in the dictionary or common words
            dictionary.contains(&clean) || common_words.contains(clean.as_str())
        })
        .collect();

    words.join(" ")
}

fn segment_words(text: &str, dictionary: &HashSet<String>) -> String {
    let n = text.len();
    if n == 0 {
        return String::new();
    }

    // dp[i] = (best_score, best_split_position)
    let mut dp: Vec<(f64, Option<usize>)> = vec![(-1e9, None); n + 1];
    dp[0] = (0.0, None);

    // Common single letter words
    let single_letter_words: HashSet<&str> = ["a", "i"].iter().cloned().collect();

    for i in 0..n {
        if dp[i].0 < -1e8 {
            continue;
        }

        // Try all possible words starting at position i
        let max_word_len = 20.min(n - i);
        for len in 1..=max_word_len {
            let j = i + len;
            let word = &text[i..j];
            let mut score = dp[i].0;

            if dictionary.contains(word) {
                // Strong preference for dictionary words, heavily weight by length
                score += (len as f64).powi(2) * 5.0;
            } else if len == 1 && single_letter_words.contains(word) {
                score += 2.0;
            } else if len <= 2 {
                // Small penalty for very short unknown words
                score -= 3.0;
            } else {
                // Strong penalty for longer unknown words
                score -= len as f64 * 8.0;
            }

            if score > dp[j].0 {
                dp[j] = (score, Some(i));
            }
        }
    }

    // Reconstruct the best segmentation
    let mut words = Vec::new();
    let mut pos = n;
    while pos > 0 {
        if let Some(prev_pos) = dp[pos].1 {
            words.push(&text[prev_pos..pos]);
            pos = prev_pos;
        } else {
            // Fallback: take one character at a time
            words.push(&text[pos - 1..pos]);
            pos -= 1;
        }
    }

    words.reverse();

    // Validate: only keep words that exist in dictionary (or are single letters a/i)
    let valid_words: Vec<String> = words.iter()
        .map(|&w| {
            if dictionary.contains(w) || w == "a" || w == "i" {
                w.to_string()
            } else {
                // Try to further segment this word
                re_segment_word(w, dictionary)
            }
        })
        .collect();

    valid_words.join(" ")
}

fn re_segment_word(word: &str, dictionary: &HashSet<String>) -> String {
    // Try to break down a non-dictionary word into smaller valid words
    let n = word.len();
    if n <= 2 {
        return word.to_string();
    }

    // Try all split points
    for i in 1..n {
        let left = &word[0..i];
        let right = &word[i..n];

        if dictionary.contains(left) && dictionary.contains(right) {
            return format!("{} {}", left, right);
        }
    }

    // Try three-way split for longer words
    if n >= 5 {
        for i in 1..n-1 {
            for j in i+1..n {
                let left = &word[0..i];
                let mid = &word[i..j];
                let right = &word[j..n];

                if dictionary.contains(left) && dictionary.contains(mid) && dictionary.contains(right) {
                    return format!("{} {} {}", left, mid, right);
                }
            }
        }
    }

    // Can't segment it, return as-is
    word.to_string()
}


fn swap_chars(text: &str, c1: char, c2: char) -> String {
    text.chars().map(|ch| {
        if ch == c1 {
            c2
        } else if ch == c2 {
            c1
        } else if ch == c1.to_ascii_uppercase() {
            c2.to_ascii_uppercase()
        } else if ch == c2.to_ascii_uppercase() {
            c1.to_ascii_uppercase()
        } else {
            ch
        }
    }).collect()
}

fn score_text(text: &str, dictionary: &HashSet<String>) -> f64 {
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut score = 0.0;
    let mut matched = 0;

    for word in &words {
        let lower = word.to_lowercase().trim_matches(|c: char| !c.is_ascii_alphabetic()).to_string();
        if !lower.is_empty() {
            if dictionary.contains(&lower) {
                // Strong bonus for dictionary words, heavily weighted by length
                score += (lower.len() as f64).powi(2) * 3.0;
                matched += 1;
            } else {
                // Penalty for non-dictionary words
                score -= 5.0;
            }
        }
    }

    // Bonus for high match ratio
    if !words.is_empty() {
        let match_ratio = matched as f64 / words.len() as f64;
        score *= 1.0 + match_ratio;
    }

    score
}

fn load_dictionary() -> Result<HashSet<String>> {
    let path = "english Dictionary.csv";
    let content = fs::read_to_string(path)
        .wrap_err_with(|| format!("failed to read dictionary file: {}", path))?;

    let mut dictionary = HashSet::new();
    for (line_no, line) in content.lines().enumerate() {
        if line_no == 0 || line.trim().is_empty() {
            continue;
        }

        if let Some(word) = line.split(',').next() {
            let word = word.trim().to_lowercase();
            // Only include words 2-15 characters long
            if word.len() >= 2 && word.len() <= 15 && word.chars().all(|c| c.is_ascii_alphabetic()) {
                dictionary.insert(word);
            }
        }
    }

    Ok(dictionary)
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
