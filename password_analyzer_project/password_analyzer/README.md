# Password Analyzer

A lightweight, offline-first Python project that evaluates password length,
character makeup, common-password matches, predictable sequences, keyboard
patterns, repetition, date-like patterns, and optional personal/context words.
It provides a Tkinter GUI and a hidden-input command-line interface.

## Requirements
- Python 3.9+
- Tkinter (usually bundled with standard Python on Windows/macOS; Linux may
  require the OS package `python3-tk`)
- No pip dependencies

## Run on Windows (PowerShell)
```powershell
py -3 main.py
```
Command-line mode:
```powershell
py -3 cli.py
```
Run tests:
```powershell
py -3 -m unittest discover -s tests -v
```

## Run on macOS/Linux
```bash
python3 main.py
python3 cli.py
python3 -m unittest discover -s tests -v
```

## What it checks
- Length and Unicode code-point count
- Lowercase, uppercase, digits, symbols, whitespace and non-ASCII characters
- Small built-in common-password blocklist, including selected predictable
  leetspeak variants
- Ascending/descending alphabetic, numeric and keyboard-row sequences
- Common keyboard runs such as `qwe`, `asd`, `zxc`
- Repeated-character runs and low character variety
- Year and common date formats
- Optional context words such as username, service or organisation name

## Scoring notes and limitations
The score is a transparent educational heuristic, not a cryptographic
measurement or guarantee of resistance to attack. The displayed entropy is
`length × log2(character-pool-size)`, a theoretical upper-bound estimate that
assumes uniformly random independent characters. Human-chosen passwords do
not satisfy that assumption, so real guessability may be much lower.

The built-in common-password list is intentionally small and is not a
substitute for a production breach-password blocklist. This application does
not query breach services, inspect malware/keyloggers, estimate attacker
hardware, or assess phishing/reuse/MFA protections. It does not store,
transmit, log, or hash the entered password.

Character-type diversity is reported as information, not required as a
composition rule. Current NIST guidance emphasizes length and blocking common,
expected or compromised passwords rather than forcing mixtures of uppercase,
lowercase, digits and symbols. For a single-factor password, NIST SP 800-63B-4
sets a 15-character minimum; passwords used only as part of MFA may be shorter
but must be at least 8 characters. Verifiers should allow at least 64
characters. Follow the target service's actual policy.

## Suggested future improvements
- Integrate a locally stored, responsibly sourced large blocklist
- Add a zxcvbn-style guessability estimator
- Add optional Have I Been Pwned range checking (k-anonymity) with explicit
  user consent and clear network disclosure
- Add multilingual dictionaries and configurable service-specific context
  words

## Academic project description
Built an offline Python password analysis tool using custom character-pool
entropy estimation and rule-based pattern detection. It identifies common,
short, repetitive, sequential, keyboard-pattern, date-based and context-based
password weaknesses, then provides actionable improvement suggestions through
a Tkinter GUI and CLI. Designed to run in lightweight environments without
third-party dependencies.

## Reference
NIST, *Digital Identity Guidelines: Authentication and Authenticator
Management*, SP 800-63B-4 (July 2025):
https://pages.nist.gov/800-63-4/sp800-63b.html
