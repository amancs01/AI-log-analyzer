# AI Log Analyzer

AI Log Analyzer is a beginner-friendly cybersecurity project that reads log files, detects suspicious activity using keyword-based rules, counts suspicious events, and calculates a basic risk level.

## Current Features

- Reads log entries from a text file.
- Detects suspicious cybersecurity keywords.
- Prints suspicious log entries.
- Counts total logs scanned.
- Counts suspicious events found.
- Calculates a basic risk level: LOW, MEDIUM, or HIGH.
- Shows the matched suspicious keyword for each detected log
- Assigns severity levels: LOW, MEDIUM, or HIGH
- Counts suspicious events by severity

## Project Status

Week 1 completed.

The project currently uses rule-based detection. It is not machine learning or real AI yet.

## Files

- `main.py` - reads and analyzes log entries.
- `sample_logs.txt` - contains normal and suspicious sample log data.
- `README.md` - project explanation.

## Risk Level Rule

- 0 suspicious events = LOW risk
- 1 to 5 suspicious events = MEDIUM risk
- More than 5 suspicious events = HIGH risk

## Example Output

```txt
[SUSPICIOUS] 2026-05-12 08:20:18 WARNING Failed login attempt for user admin from 203.0.113.45
[SUSPICIOUS] 2026-05-12 09:05:42 ALERT Possible brute force attack from 203.0.113.45

--- Security Summary ---
Total logs scanned: 42
Suspicious events found: 26
Risk level: HIGH

- Uses separate functions for detection, severity counting, risk calculation, and report printing
- Uses a main() function as the program entry point