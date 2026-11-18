# ConnectCheck – Network Diagnostics and Packet Analysis Tool

## 1. Project Overview

ConnectCheck is a Python-based network diagnostics and packet analysis tool designed to help users investigate common network connectivity issues.

The application performs DNS resolution, ICMP ping tests, HTTP/HTTPS checks, and SSL/TLS certificate validation for a given domain. It also provides a PCAP analyzer that examines captured network traffic to identify DNS, TCP, HTTP, and TLS-related information.

A rule-based diagnosis engine combines diagnostic results to identify probable causes and suggest troubleshooting steps. Users can also generate PDF reports containing diagnostic results and packet analysis findings.

## 2. Key Features

### Network Diagnostics
- **DNS Resolution:** Resolves domain names into IP addresses.
- **Ping Test:** Checks host reachability using ICMP packets.
- **HTTP/HTTPS Check:** Examines web server responses, HTTP status codes, and connectivity.
- **SSL/TLS Certificate Check:** Validates certificates and displays certificate information, TLS version, and expiry details.

### Rule-Based Diagnosis
- Combines the results of individual network checks.
- Identifies probable causes of connectivity issues.
- Categorizes problems into areas such as DNS, Network, Web Server, TLS Certificate, and Access.
- Provides actionable troubleshooting recommendations.

### PCAP Analysis
- Supports `.pcap` and `.pcapng` capture files.
- Analyzes DNS queries and responses.
- Examines TCP flags, connection attempts, and reset packets.
- Identifies HTTP requests and response status codes when visible in captured traffic.
- Extracts TLS handshake metadata, including ClientHello and ServerHello information.
- Displays protocol statistics and packet samples.
- Highlights potential network issues through packet analysis findings.

### PDF Report Generation
- Generates downloadable network diagnostic reports.
- Generates PCAP analysis reports.
- Includes packet statistics, findings, evidence, possible explanations, and recommendations.

### Upload Validation
- Checks uploaded file extensions.
- Rejects empty and invalid capture files.
- Enforces a maximum upload size of 10 MB.
- Uses secure filenames and temporary upload storage.
- Removes temporary uploaded files after analysis.

## 3. Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application and diagnostic logic |
| Flask | Web application and routing |
| Scapy | PCAP reading and packet analysis |
| Socket | DNS and network connectivity operations |
| Requests | HTTP/HTTPS requests |
| SSL | TLS certificate verification |
| ReportLab | PDF report generation |
| HTML | Frontend structure |
| CSS | Frontend styling |
| Jinja2 | Dynamic HTML rendering |
| Pytest | Automated testing |

## 4. System Architecture

ConnectCheck consists of two main workflows.

### A. Network Diagnostics Workflow

1. The user enters a domain through the web interface.
2. Flask receives the submitted domain.
3. The domain is validated.
4. The diagnostic modules perform DNS, ping, HTTP/HTTPS, and SSL/TLS checks.
5. The diagnosis engine evaluates the results.
6. The application displays findings and recommendations.
7. The user can download a PDF report.

### B. PCAP Analysis Workflow

1. The user uploads a PCAP or PCAPNG file.
2. Flask validates the uploaded file.
3. Scapy reads the packet capture.
4. The analyzer extracts protocol-specific information.
5. The analyzer identifies potential network issues.
6. The results are displayed on the PCAP analysis page.
7. A PDF report can be generated from the analysis.

## 5. Project Structure

```text
ConnectCheck/
│
├── app.py
├── diagnosis.py
├── report.py
├── requirements.txt
├── README.md
│
├── checks/
│   ├── __init__.py
│   ├── common.py
│   ├── dns_check.py
│   ├── ping_check.py
│   ├── http_check.py
│   └── ssl_check.py
│
├── analyzer/
│   ├── __init__.py
│   └── pcap_analyzer.py
│
├── templates/
│   ├── index.html
│   └── analyzer.html
│
├── static/
│   └── style.css
│
├── samples/
│   ├── sample.pcap
│   └── sample.pcapng
│
├── tests/
│   ├── test_common.py
│   ├── test_diagnosis.py
│   ├── test_dns_check.py
│   ├── test_ping_check.py
│   ├── test_http_check.py
│   ├── test_ssl_check.py
│   ├── test_pcap_analyzer.py
│   └── test_report.py
│
└── uploads/
```

## 6. Installation and Setup

### Prerequisites

- Python installed
- Visual Studio Code or another Python editor
- Git (optional, for cloning the repository)

### Step 1: Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd ConnectCheck
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with the actual repository URL.

Alternatively, download and extract the project ZIP file.

### Step 2: Create a virtual environment

```powershell
python -m venv venv
```

### Step 3: Activate the virtual environment

```powershell
.\venv\Scripts\Activate.ps1
```

### Step 4: Install dependencies

```powershell
python -m pip install -r requirements.txt
```

## 7. Running the Application

Start the Flask application:

```powershell
python app.py
```

Open the following address in your browser:

```text
http://127.0.0.1:5000
```

The application provides two main sections:

- **Network Diagnostics:** Enter a domain to perform connectivity checks.
- **PCAP Analysis:** Upload a packet capture to inspect network traffic.

To stop the Flask development server, press `Ctrl + C` in the terminal.

## 8. Using the PCAP Analyzer

1. Open the PCAP Analysis page.
2. Select a `.pcap` or `.pcapng` file.
3. Click **Analyze Capture**.
4. Review the analysis summary and protocol statistics.
5. Examine DNS, TCP, HTTP, and TLS information.
6. Review the detected network findings.
7. Download the PDF analysis report.

Sample capture files are available in the `samples/` directory.

**Note:** The included sample captures contain synthetic test traffic designed to demonstrate the analyzer's capabilities.

## 9. Generating PDF Reports

ConnectCheck supports PDF report generation for:

- Network diagnostic results, including individual checks and probable root causes.
- PCAP analysis results, including packet statistics, findings, evidence, and recommendations.

Reports can be downloaded directly through the web interface.

## 10. Running Automated Tests

The project uses Pytest for automated testing.

Run the complete test suite:

```powershell
python -m pytest tests/ -v
```

The tests cover:

- Domain validation and common utilities.
- DNS resolution.
- Ping functionality.
- HTTP/HTTPS checks.
- SSL/TLS certificate validation.
- Diagnosis engine logic.
- PCAP analysis.
- PDF report generation.

The test suite includes success cases, failure cases, invalid inputs, and simulated network errors.

## 11. Important Limitations

- Ping failures do not necessarily mean a host is unavailable because ICMP traffic may be blocked.
- Packet analysis is based on the traffic available in the uploaded capture.
- HTTPS application data is encrypted; the analyzer extracts available protocol metadata and does not decrypt HTTPS traffic.
- HTTP details may be unavailable when traffic is encrypted or packet information is incomplete.
- Packet-level observations indicate possible issues and do not always establish their exact cause.
- The diagnosis engine uses predefined rules rather than machine learning.
- The current application is designed as a local development tool, not a production deployment.

## 12. Future Enhancements

- Add live network packet capture.
- Improve TCP stream reassembly.
- Expand protocol analysis.
- Add more advanced network anomaly detection.
- Improve visualization of packet statistics.
- Add authentication and user-specific report history.
- Introduce more detailed troubleshooting recommendations.
- Support deployment in a production environment.

## 13. Project Objective

The main objective of ConnectCheck is to combine commonly used network troubleshooting techniques with packet-level analysis in one web application.

By integrating connectivity checks, packet inspection, rule-based diagnosis, and downloadable reports, the project provides a structured way to investigate network problems and understand the underlying communication behavior.

---

**ConnectCheck – Network Diagnostics and Packet Analysis Tool**

Developed using Python, Flask, Scapy, and ReportLab.