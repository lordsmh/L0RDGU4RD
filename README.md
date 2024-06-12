البته، این یک فایل README برای ابزار اسکن SSL به زبان انگلیسی است:
# SSL Vulnerability Scanner

## Introduction
SSL Vulnerability Scanner is a Python tool designed to scan SSL certificates for common vulnerabilities and weaknesses. It provides a command-line interface for users to specify the site they want to scan and select which vulnerabilities to check for.

## Features
- Checks for common SSL vulnerabilities such as POODLE and Heartbleed.
- Additional checks for BEAST, CRIME, and FREAK vulnerabilities.
- Displays detailed information about the SSL certificate, including subject, issuer, validity period, and certificate algorithm.
- Allows users to specify which vulnerabilities to check using command-line options.
- Provides clear warnings if vulnerabilities are detected during the scan.

## Installation
1. Clone the repository:
   ```
   git clone https://github.com/LordSmh/SSL-Vulnerability-Scanner.git
   ```
2. Navigate to the project directory:
   ```
   cd SSL-Vulnerability-Scanner
   ```
3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage
To scan a website for SSL vulnerabilities, run the `ssl_scan.py` script with the desired options. Here's the basic usage syntax:
```
python ssl_scan.py <site> [--poodle] [--heartbleed] [--beast] [--crime] [--freak]
```
- `<site>`: The website URL to scan (e.g., example.com).
- `--poodle`: Check for POODLE vulnerability.
- `--heartbleed`: Check for Heartbleed vulnerability.
- `--beast`: Check for BEAST vulnerability.
- `--crime`: Check for CRIME vulnerability.
- `--freak`: Check for FREAK vulnerability.

Example:
```
python ssl_scan.py example.com --poodle --heartbleed
```

## Credits
SSL Vulnerability Scanner is created by LordSmh. Contributions and feedback are welcome!

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
