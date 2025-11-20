# Monoalphabetic Substitution Cipher Solver

This is a command-line tool written in Rust to solve monoalphabetic substitution ciphers. It uses a combination of frequency analysis, a dictionary, and a hill-climbing search algorithm to find the most likely plaintext for a given ciphertext.

# Students
- Coutin (Rafael Coutinho)
- Mister (Davi Arantes)

## How it Works

The solver employs a sophisticated approach to decryption:

1.  **Frequency Analysis**: It starts by analyzing the frequency of single letters (monograms), pairs of letters (bigrams), and triplets of letters (trigrams) in the ciphertext. This frequency data is compared against standard English letter and n-gram frequencies to make an initial guess for the substitution key.

2.  **Hill-Climbing Algorithm**: The core of the solver is a hill-climbing algorithm. It starts with the initial frequency-based key and then iteratively makes small changes (swapping two letters in the key) to see if the change results in a "better" plaintext.

3.  **Scoring**: The "betterness" of a plaintext is determined by a scoring function. This function calculates a score based on:
    *   The log-probability of the letter, bigram, and trigram frequencies in the decrypted text.
    *   The number of valid English words found in the decrypted text.

4.  **Dictionary and Soundex**: A dictionary of English words is used to check the validity of the decrypted words. The Soundex algorithm is also used to identify words that sound correct, even if they are not spelled perfectly. This helps to guide the search towards a correct solution.

5.  **Random Restarts**: To avoid getting stuck in local optima, the hill-climbing algorithm is restarted multiple times with slightly different starting keys.

6.  **Word Segmentation and Correction**: After the main decryption process, the tool performs a final pass to segment the continuous stream of letters into words and correct common errors.

## Usage

To use the solver, you can provide the ciphertext in one of three ways:

1.  **From a file:**
    ```bash
    cargo run -- -f /path/to/your/ciphertext.txt
    ```

2.  **As a command-line argument:**
    ```bash
    cargo run -- "your ciphertext here"
    ```

3.  **From standard input:**
    ```bash
    echo "your ciphertext here" | cargo run
    ```

### Options

*   `-f, --file <FILE>`: Path to a file containing the ciphertext.
*   `-s, --steps <STEPS>`: The number of hill-climbing steps to perform for each restart (default: 30000).
*   `-r, --restarts <RESTARTS>`: The number of times to restart the search with a different key (default: 50).

## Building from Source

To build the project, you need to have Rust and Cargo installed.

1.  Clone the repository:
    ```bash
    git clone <repository-url>
    ```
2.  Navigate to the project directory:
    ```bash
    cd crypto
    ```
3.  Build the project:
    ```bash
    cargo build --release
    ```
4.  The executable will be located at `target/release/crypto`.
