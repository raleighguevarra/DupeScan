# DupeScan: Advanced Phishing & Impersonation Detector

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/Security-Antiphishing-red)](#security)

## What is DupeScan?

DupeScan is an advanced phishing and impersonation detection tool that helps identify:
- Fake domains impersonating your brand
- Phishing websites attempting to steal credentials
- Typosquatting and domain hijacking attempts
- SSL and website content anomalies
- Logo similarity detection to catch visual scams

Using Open-Source Intelligence (OSINT) techniques, DupeScan extracts data from Bing search results, URLHaus, OpenPhish, WHOIS records, SSL certificates, and website content to flag suspicious websites mimicking a real domain.

## Features

- Multi-Layer Phishing Detection – Combines domain intelligence, content scanning, and image hashing for accuracy.  
- Typosquatting & URL Hijacking Detection – Identifies misspelled, homoglyphic, and deceptive domains.  
- Website Content Analysis – Scans text, meta tags, forms, and JavaScript for phishing keywords.  
- SSL Certificate Inspection – Analyzes issuer and subject details to detect mismatched SSL certs.  
- Logo Similarity Detection – Uses pHash (Perceptual Hashing) to check if fake sites use stolen brand assets.  
- Comprehensive Reports – Outputs results in CSV and JSON formats for analysis and evidence collection.  
- Command-Line Friendly – Simple CLI usage with detailed scanning progress.  

## Installation

### Prerequisites

- Python 3.8+ (Recommended)  
- pip (Python package manager)  

### Clone the Repository

```sh
git clone https://github.com/raleighguevarra/DupeScan.git
cd DupeScan
```

### Install Dependencies

```sh
pip install -r requirements.txt
```

## Usage

### Display Help Menu

```sh
python dupescan.py --help
```

#### Example Output:

```
usage: dupescan.py [-h] [--logo LOGO] original_url

Detect phishing, typosquatting, and impersonating websites.

positional arguments:
  original_url    The official website to check for impersonators (e.g., example.com)

optional arguments:
  -h, --help      Show this help message and exit
  --logo LOGO     URL of the original website's logo for comparison
```

## Sample Executions & Features Showcase

### Basic Scan: Detect Fake & Phishing Websites

```sh
python dupescan.py example.com
```

### Advanced Scan: Include Logo Similarity Check

```sh
python dupescan.py example.com --logo "https://www.example.com/images/logo2.png"
```

## Output Formats

| Domain                        | Risk Level                | SSL Issuer      | Phishing Indicators              |
|--------------------------------|---------------------------|-----------------|----------------------------------|
| fake-example-login.com       | High Risk - Phishing   | Let's Encrypt  | Login, Mentions Original Domain |
| example-secure.com           | Suspicious - Needs Review | Unknown       | Secure Form Detected           |

## Security Considerations

- DupeScan does not interact with malicious websites beyond retrieving public content.  
- Always run DupeScan in a safe environment to avoid accidental execution of malicious scripts.  
- Use a VPN or sandboxed system if scanning highly suspicious domains.  

## Roadmap & Future Improvements

- Phase 1: Implement domain intelligence, SSL checks, and content analysis.  
- Phase 2: Add logo similarity detection using perceptual hashing (pHash).  
- Phase 3: Integrate AI/ML for phishing risk scoring.  
- Phase 4: Provide real-time scanning with a headless browser for deeper phishing detection.  

## License

This project is licensed under the MIT License – See the [LICENSE](LICENSE) file for details.  

## Contributing

We welcome contributions! If you want to improve DupeScan:  

1. Fork the repository  
2. Create a feature branch  
3. Submit a pull request  

For major changes, please open an issue first to discuss your proposal.  

## Contact

For questions, bug reports, or feature requests, feel free to open an issue or reach out via GitHub Discussions.  

DupeScan – Because cybersecurity starts with detection!
