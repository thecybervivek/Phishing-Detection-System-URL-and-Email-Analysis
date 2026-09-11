# Phishing Detection System

A Flask-based heuristic phishing detection system that analyzes URLs and email/text content for suspicious indicators.

## Live Demo

Live Application: https://phishing-detection-system-url-and-email-analysis.onrender.com

Note: The application is hosted on Render's free instance, so the first request may take some time after inactivity.

## Project Objective

The objective of this project is to identify potentially suspicious URLs and phishing-related email/text content using heuristic analysis techniques.

The system analyzes user-provided input and generates a risk score, classification, and detected indicators.

## Features

- URL analysis
- Email/Text analysis
- Suspicious keyword detection
- Suspicious URL pattern detection
- HTTP/HTTPS analysis
- URL shortener detection
- IP address based URL detection
- `@` symbol detection in URLs
- Long URL detection
- Multiple subdomain detection
- Multiple hyphen detection
- Urgency/pressure language detection
- Credential-related keyword detection
- Prize/reward related keyword detection
- Risk score from 0–100
- Phishing classification
- Detected security indicators
- Does not open or execute submitted URLs

## Risk Classification

The system classifies analyzed input based on its calculated risk score.

- Below 30: Likely Safe
- 30–59: Suspicious
- 60–100: Likely Phishing

## Technologies Used

- Python
- Flask
- HTML5
- CSS3
- Jinja2
- Gunicorn

## URL Analysis

The URL analysis checks different characteristics of a submitted URL, including:

- HTTPS usage
- URL shortener domains
- IP address based URLs
- `@` symbol
- URL length
- Multiple subdomains
- Multiple hyphens
- Suspicious keywords
- Unusual URL patterns

The system combines detected indicators into a risk score and provides a final classification.

## Email/Text Analysis

The email/text analyzer checks for indicators commonly associated with phishing messages, including:

- Suspicious keywords
- Urgency or pressure language
- Credential-related terms
- Links
- Prize or reward related language
- Email addresses

The detected indicators contribute to the overall risk score and classification.

## Testing

The following scenarios were tested:

1. Safe URL analysis
2. Suspicious URL analysis
3. Suspicious keyword detection
4. HTTP/HTTPS detection
5. Multiple hyphen detection
6. Email/Text phishing analysis
7. Urgency language detection
8. Credential-related keyword detection
9. Risk score generation
10. Safe, Suspicious, and Likely Phishing classification

## Example Results

### URL Analysis

Example suspicious URL:

http://paypal-login-security.example.com/verify-account

Example result:

Risk Score: 40/100

Classification: Suspicious

Detected indicators include:

- URL does not use HTTPS
- Domain contains multiple hyphens
- Suspicious keywords such as account, login, security, and verify

### Email/Text Analysis

Example phishing-style text:

URGENT! Your account has been suspended.

Click here to verify your account immediately and confirm your password.

You have won a prize. Claim your reward now.

Example result:

Risk Score: 60/100

Classification: Likely Phishing

Detected indicators include:

- Suspicious keywords
- Urgency/pressure language

## Security Considerations

This project performs heuristic analysis and does not rely on opening or executing submitted URLs.

It is designed for cybersecurity learning and demonstration purposes.

The system is not a replacement for browser reputation services, sandboxing, SPF/DKIM/DMARC validation, threat intelligence platforms, or commercial phishing detection engines.

Do not open suspicious links.

## Deployment

The application is deployed on Render using Gunicorn.

Build Command:

pip install -r requirements.txt

Start Command:

gunicorn app:app

## Internship Task

Internship: Cyber Security Intern – IncodeVision

Task : Phishing Detection System (URL & Email Analysis)

The project demonstrates basic phishing detection through heuristic URL and email/text analysis, suspicious indicator detection, risk scoring, and phishing classification.

## Author

Vivek Sharma

Cyber Security Student & Intern

## Disclaimer

This project was developed for educational and internship purposes to demonstrate basic phishing detection and security analysis concepts.

The results are heuristic-based and should not be treated as definitive proof that a URL or email is safe or malicious.
