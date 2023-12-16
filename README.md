
# Secure File Scan

Secure File Scan is a threat intelligence-based website that provides malware detection and analysis services. It includes a dedicated database for malware detection, API integration, and a reporting portal for malware researchers.


## Demo

Insert gif or link to demo

## Features

- **Malware Detection:** Scan uploaded files for malware using a comprehensive threat intelligence database.
- **Detailed Information:** Retrieve detailed information and YARA rules for identified malware.
- **API Integration:** Integrated Flask-based API and external malware analyzing APIs for enhanced research capabilities.
- **Malware Reporting Portal:** Allows malware researchers to report new malware to the database.
- **Real-time Dashboard:** Displays real-time information on recent cyber attacks, reported malware, IOCs, top countries in threat intelligence, and a pie chart showing the distribution of companies affected by phishing attacks.
## API Reference

#### Get all items

```http
  GET /api/items
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `api_key` | `string` | **Required**. Your API key |

#### Get item

```http
  GET /api/items/${id}
```

| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `id`      | `string` | **Required**. Id of item to fetch |

#### add(num1, num2)

Takes two numbers and returns the sum.


## Documentation

[Documentation](https://linktodocumentation)


## Acknowledgements

 - [Awesome Readme Templates](https://awesomeopensource.com/project/elangosundar/awesome-README-templates)
 - [Awesome README](https://github.com/matiassingers/awesome-readme)
 - [How to write a Good readme](https://bulldogjob.com/news/449-how-to-write-a-good-readme-for-your-github-project)


## Problem Solved

Secure File Scan addresses the need for a centralized platform for malware detection and research. By combining a robust threat intelligence database, API integration, and a reporting portal, it streamlines the process for users, eliminating the need to visit multiple websites for malware analysis.
## Usage

To use the Secure File Scan project, follow these steps:

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/secure-file-scan.git
   cd secure-file-scan
   python app.py
## Authors
- [@Zain Ali Raza](https://www.linkedin.com/in/zain-ali-raza-7372b1219/)
- [@Sarim Muhammad khan](https://www.linkedin.com/in/sarim-mohammed-khan-65bb921a3/)
- [@Mehdi Badami](https://www.linkedin.com/in/mehdi-badami-bb1509258/)
- [@Moiz Ullah Siddiqui](https://www.linkedin.com/in/moiz-sid/)
## License

[MIT](https://choosealicense.com/licenses/mit/)




## References

1. VirusTotal API Documentation and references,
   [VirusTotal API](https://docs.virustotal.com/reference/public-vs-premium-api)

2. Malware Bazaar API Documentation and references,
   [Malware Bazaar API](https://bazaar.abuse.ch/api/)

3. Color Psychology in UI Design,
   [Color Psychology](www.example.com/color-psychology)

4. Effective Information Presentation Strategies,
   [Information Presentation Strategies](www.example.com/information-presentation)

5. User-Centric Design Principles,
   [User-Centric Design Principles](www.example.com/user-centric-design)

6. Python Logging Documentation,
   [Python Logging](https://docs.python.org/3/library/logging.html)

7. Operational Efficiency in Cybersecurity Platforms,
   [Operational Efficiency](www.example.com/operational-efficiency-cybersecurity)

8. SSL/TLS Overview,
   [SSL/TLS Overview](www.example.com/ssl-tls-overview)

9. Florian Roth, the creator of Yara Rules,
   [Florian Roth - Yara Rules](https://github.com/Neo23x0)
