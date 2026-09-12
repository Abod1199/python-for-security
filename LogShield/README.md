# LogShield - Security Log Analyzer

## About the Project

LogShield is a Python project I built to practice Python programming in a cybersecurity use case.

The idea of the project is to analyze a security log file, extract useful information from the logs, detect repeated failed login attempts, and generate a simple threat assessment.

The program also saves the final analysis in a JSON report.

## Features

- Read security logs from a text file
- Extract timestamps, log levels, messages, and IP addresses
- Count INFO, WARNING, and ERROR events
- Detect repeated failed login attempts
- Identify suspicious IP addresses
- Calculate a threat score
- Classify the threat as LOW, MEDIUM, or HIGH
- Save the analysis as a JSON report
- Handle file-related errors
- Test the main functions using pytest

## Project Structure

```text
LogShield/
│
├── data/
│   └── sample_logs.txt
│
├── reports/
│   └── triage_report.json
│
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── models.py
│   ├── parser.py
│   ├── triage.py
│   └── utils.py
│
├── tests/
│   └── test_triage.py
│
├── .gitignore
├── requirements.txt
└── README.md
```

## How It Works

The program follows this process:

```text
Security Log File
       |
       v
   Log Parser
       |
       v
  LogEvent Objects
       |
       v
 Security Analysis
       |
       v
   Threat Score
       |
       v
   Threat Level
       |
       v
   JSON Report
```

First, the program reads the log file from the `data` folder.

The parser uses regular expressions to separate each log into:

- Timestamp
- Log level
- Message
- IP address

After parsing the logs, the program checks for repeated failed login attempts.

If the same IP address has 3 or more failed login attempts, it is marked as suspicious.

## Threat Scoring

I used a simple rule-based scoring system:

| Event | Points |
|---|---:|
| ERROR | +1 |
| WARNING | +2 |
| Suspicious IP | +3 |

The final score is classified into three levels:

| Score | Threat Level |
|---|---|
| 0 - 2 | LOW |
| 3 - 5 | MEDIUM |
| 6+ | HIGH |

## Example

For the sample log file, LogShield detected:

```text
Total Events: 8
INFO: 3
WARNING: 1
ERROR: 4

Suspicious IPs:
- 10.0.0.5: 4 failed login attempts

Threat Score: 9
Threat Level: HIGH
```

## Technologies Used

- Python
- Regular Expressions (Regex)
- Object-Oriented Programming (OOP)
- JSON
- pathlib
- Rich
- pytest
- Git and GitHub

## Installation

Clone the repository:

```bash
git clone https://github.com/Abod1199/python-for-security.git
```

Go to the project directory:

```bash
cd python-for-security/LogShield
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the required packages:

```bash
python -m pip install -r requirements.txt
```

## Run the Project

Run LogShield from the project directory:

```bash
python -m src.main
```

The program will analyze:

```text
data/sample_logs.txt
```

and generate the report in:

```text
reports/triage_report.json
```

## Testing

The project includes unit tests for the main analysis functions.

Run the tests using:

```bash
python -m pytest
```

Current test result:

```text
4 passed
```

## What I Learned

While working on this project, I practiced:

- Reading and writing files in Python
- Using regular expressions to extract data
- Working with classes and objects
- Splitting a Python project into modules
- Using dictionaries and lists
- Error handling
- Working with JSON
- Creating simple security detection rules
- Writing unit tests with pytest
- Using external Python packages
- Using Git and GitHub

## Future Improvements

In the future, I would like to improve LogShield by adding:

- More security detection rules
- Better IPv4 address validation
- Detection of brute-force attacks based on time
- Support for CSV and JSON logs
- More detailed reports
- Log visualization and charts
- Support for larger real-world log files

## Disclaimer

This project was created for educational purposes to practice Python and basic cybersecurity log analysis.