# Task 04 — Phishing Detection System (URL & Email Analysis)

IncodeVision Cyber Security Internship task implementation.

## Requirements covered
- URL input analysis
- Email/text input analysis
- Suspicious keyword detection
- URL pattern checks
- IP-address URL detection
- URL shortener detection
- `@` and excessive-subdomain heuristics
- HTTPS check
- Risk score and classification
- Human-readable indicators

## Run
```bash
python -m venv venv
# Windows
venv\Scripts\activate

pip install -r requirements.txt
python app.py
```
Open: `http://127.0.0.1:5000`

## Safe demo test inputs

URL:
`https://example.com/login`

Suspicious URL:
`http://192.0.2.10/verify-account/login`

Email:
`URGENT: Your account is suspended. Verify your password immediately by clicking the link.`

> Use only safe test strings. This project performs static heuristic analysis and does not visit or execute submitted URLs.