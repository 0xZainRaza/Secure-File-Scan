
![secure_file_scan (3)](https://github.com/0xZainRaza/Secure-File-Scan/assets/98187755/8604fa41-14a0-4004-8f08-e0d18ee4af79)
![logo (3)](https://github.com/0xZainRaza/Secure-File-Scan/assets/98187755/dfbbd887-9b58-4b47-994a-887b90c82c25)







Secure File Scan is a threat intelligence-based website that provides malware detection and analysis services. It includes a dedicated database for malware detection, API integration, and a reporting portal for malware researchers.


[![GitHub license](https://img.shields.io/github/license/creecros/simple_logo_gen.svg)](https://github.com/0xZainRaza/Secure-File-Scan/blob/main/LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/0xZainRaza/Secure-File-Scan/graphs/contributors)


## Demo

Insert gif or link to demo



## Proposed Solution

In the realm of cybersecurity, the proliferation of malware poses a constant threat to individuals and organizations alike. **Secure File Scan** steps in to alleviate this concern by offering a comprehensive and centralized solution for malware detection and research. The multifaceted approach taken by **Secure File Scan** addresses several critical aspects of cybersecurity:

1. **Efficient Detection:** The platform employs a sophisticated threat intelligence database, enabling swift and accurate detection of malware within uploaded files. This not only minimizes the risk of potential infections but also saves valuable time for users.

2. **Holistic Information Retrieval:** **Secure File Scan** goes beyond mere detection by providing users with detailed information and YARA rules for identified malware. This empowers cybersecurity professionals and researchers with the insights needed to understand the nature of threats and devise effective mitigation strategies.

3. **Seamless API Integration:** Through its integrated Flask-based API and external malware analyzing APIs, **Secure File Scan** enhances research capabilities. This integration ensures that users have access to a diverse set of tools and resources, fostering a more collaborative and informed cybersecurity community.

4. **Community-Driven Reporting Portal:** The inclusion of a reporting portal encourages active participation from malware researchers. By allowing them to report new malware to the database, **Secure File Scan** leverages collective intelligence to stay ahead of emerging threats, contributing to a more secure online environment.

By consolidating these features into a single platform, **Secure File Scan** eliminates the need for users to navigate disparate sources for malware analysis. This unified approach not only enhances the overall efficiency of cybersecurity efforts but also promotes a shared responsibility in combating the evolving landscape of cyber threats.

## Requirements

Ensure you have Python3.10 or above along with these libraries:

#### Dependencies

- Flask and its dependencies
- hashlib
- flask_sqlalchemy
- flask_login
- flask_wtf
- wtforms
- flask_bcrypt
- werkzeug
- requests
- subprocess
- logging

#### install

Install the required Python libraries using the following command:

    pip install -r requirements.txt



## Usage

To use the Secure File Scan project, follow these steps:

1. Clone the repository:

   ```bash
   git clone https://github.com/0xZainRaza/secure-file-scan.git
   cd secure-file-scan
   python app.py

## Features

- **Malware Detection:** Scan uploaded files for malware using a comprehensive threat intelligence database.
- **Detailed Information:** Retrieve detailed information and YARA rules for identified malware.
- **API Integration:** Integrated Flask-based API and external malware analyzing APIs for enhanced research capabilities.
- **Malware Reporting Portal:** Allows malware researchers to report new malware to the database.
- **Real-time Dashboard:** Displays real-time information on recent cyber attacks, reported malware, IOCs, top countries in threat intelligence, and a pie chart showing the distribution of companies affected by phishing attacks.
- **Data Encryption:** Utilizes Blowfish encryption algorithm for secure data storage. Bcrypt is employed with a 128-bit salt and encrypts a 192-bit magic value, taking advantage of the expensive key setup in eksblowfish.


# API Reference

## VirusTotal API

#### Scan File for Malware

Submit a file for scanning and get the analysis report.

```http
POST /api/virustotal/scan
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `File` | `file` | **Required**.  File to scan |

[FULL Documentation VirusTotal API](https://docs.virustotal.com/reference/post_files)


## Malware Bazaar API

*Get Recent Malware Samples*

Retrieve information on recent malware samples.

```
GET /api/malwarebazaar/recent
```
| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `limit` | `integer` |   Number of recent samples to retrieve. |
| `format` | `string` |   Output format (json or text). |


[FULL Documentation malwarebazaar API](https://bazaar.abuse.ch/api/)

## Authors
- [Zain Ali Raza](https://www.linkedin.com/in/zain-ali-raza-7372b1219/)
- [Sarim Muhammad khan](https://www.linkedin.com/in/sarim-mohammed-khan-65bb921a3/)
- [Mehdi Badami](https://www.linkedin.com/in/mehdi-badami-bb1509258/)
- [Moiz Ullah Siddiqui](https://www.linkedin.com/in/moiz-sid/)


## References

1. Python Logging Documentation,
   [Python Logging](https://docs.python.org/3/library/logging.html)

2. SSL/TLS Overview,
   [SSL/TLS Overview](www.example.com/ssl-tls-overview)

3. Florian Roth, the creator of Yara Rules,
   [Florian Roth - Yara Rules](https://github.com/Neo23x0)
