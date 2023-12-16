# Secure File Scan

Secure File Scan is a threat intelligence-based website that provides malware detection and analysis services. It includes a dedicated database for malware detection, API integration, and a reporting portal for malware researchers.

## Features

- **Malware Detection:** Scan uploaded files for malware using a comprehensive threat intelligence database.
- **Detailed Information:** Retrieve detailed information and YARA rules for identified malware.
- **API Integration:** Integrated Flask-based API and external malware analyzing APIs for enhanced research capabilities.
- **Malware Reporting Portal:** Allows malware researchers to report new malware to the database.
- **Real-time Dashboard:** Displays real-time information on recent cyber attacks, reported malwares, IOCs, top countries in threat intelligence, and a pie chart showing the distribution of companies affected by phishing attacks.

## Problem Solved

Secure File Scan addresses the need for a centralized platform for malware detection and research. By combining a robust threat intelligence database, API integration, and a reporting portal, it streamlines the process for users, eliminating the need to visit multiple websites for malware analysis.

## Usage

To use the Secure File Scan project, follow these steps:

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/secure-file-scan.git
   cd secure-file-scan
   python app.py
