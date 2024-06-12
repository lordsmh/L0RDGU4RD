# L0rdGu4rd

**L0rdGu4rd** is a powerful SSL/TLS vulnerability scanner designed to identify common security flaws in websites. This tool helps administrators and security enthusiasts quickly assess the security status of their SSL/TLS configurations.

## Features

- **SSL/TLS Certificate Information:** Extracts and displays details such as subject, issuer, validity period, and signature algorithm.
- **Protocol Version Check:** Identifies and warns about the use of vulnerable SSL/TLS versions.
- **Vulnerability Scanning:** Detects common vulnerabilities including POODLE, Heartbleed, BEAST, CRIME, and FREAK.
- **Random User-Agent:** Uses a random User-Agent string to avoid request blocking.
- **Automated Scanning:** Option to scan for all vulnerabilities simultaneously.

## Installation

Ensure you have Python installed on your system. Then, install the required libraries using `pip`:

```bash
pip install pyopenssl
```

## Usage

### Basic Usage

To scan a website for all vulnerabilities:

```bash
python L0rdGu4rd.py --url https://example.com --all
```

### Specific Vulnerability Scans

To check for specific vulnerabilities, use the respective switches:

- POODLE: 
  ```bash
  python L0rdGu4rd.py --url https://example.com --poodle
  ```

- Heartbleed:
  ```bash
  python L0rdGu4rd.py --url https://example.com --heartbleed
  ```

- BEAST:
  ```bash
  python L0rdGu4rd.py --url https://example.com --beast
  ```

- CRIME:
  ```bash
  python L0rdGu4rd.py --url https://example.com --crime
  ```

- FREAK:
  ```bash
  python L0rdGu4rd.py --url https://example.com --freak
  ```

### Random User-Agent

To use a shorter random User-Agent string:

```bash
python L0rdGu4rd.py --url https://example.com --short-user-agent --all
```

### Help

For a complete list of options and usage instructions:

```bash
python L0rdGu4rd.py -h
```

## Command Line Options

```text
-u, --url            The URL of the site to scan (e.g., https://example.com)
-a, --all            Scan for all vulnerabilities
-p, --poodle         Check for POODLE vulnerability
-hb, --heartbleed    Check for Heartbleed vulnerability
-b, --beast          Check for BEAST vulnerability
-c, --crime          Check for CRIME vulnerability
-f, --freak          Check for FREAK vulnerability
-s, --short-user-agent
                     Use a shorter random User-Agent
```

## Example

To scan https://example.com for all vulnerabilities using a short User-Agent:

```bash
python L0rdGu4rd.py -u https://example.com -a -s
```

## Author

Created by **LordSmh** from the (**H4ckL0rd5**)[lordsmh.github.io] group
.
