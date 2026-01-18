# Safe Web Vulnerability Checker (SWVC)

**Safe Web Vulnerability Checker** is a passive, educational cybersecurity tool designed to analyze web security configurations without performing any active exploitation. It helps developers and students understand HTTP security mechanisms, header configurations, and CORS policies.

## 🚀 Features

*   **Passive Analysis:** Safe to use on any target; strictly performs `GET`/`HEAD` requests.
*   **HTTPS Enforcement Check:** Verifies if HTTP traffic is properly redirected to HTTPS.
*   **Security Headers Analysis:** Checks for missing or misconfigured headers (HSTS, CSP, X-Frame-Options, etc.).
*   **CORS Policy Validation:** Detects risky Cross-Origin Resource Sharing configurations (e.g., wildcards with credentials).
*   **Session Management:** Automatically logs every scan session with timestamps and unique IDs.
*   **Multiple Output Formats:**
    *   Interactive CLI Menu.
    *   Command-line arguments.
    *   JSON and Markdown report export.

---

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-repo/SWVC.git
    cd SWVC
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---

## 📖 Usage

You can use the tool in two modes: **Interactive Mode** (Menu-based) or **Command Line Mode**.

### 1. Interactive Mode
Simply run the script without arguments to enter the menu:
```bash
python main.py
```
From here you can:
*   Create a new session (Enter URL).
*   View session history.
*   Run scans on the active session.

### 2. Command Line Mode (CLI)

The tool supports direct commands for automation and quick scanning.

#### Scan a Target
Basic scan (prints report to terminal):
```bash
python main.py scan https://example.com
```

#### Scan and Save Report
Export results to JSON or Markdown:
```bash
python main.py scan https://example.com --json report.json --markdown report.md
```

#### Verbose Output
See more details during execution:
```bash
python main.py scan https://example.com -v
```

#### View History
List recent scan sessions:
```bash
python main.py history --limit 5
```

#### Show Specific Session
View details of a past scan using its Session ID:
```bash
python main.py show SWVC-20240118-123045-example-a1b2c3d4
```

---

## 📂 Project Structure

*   **`main.py`**: Entry point for both CLI and interactive modes.
*   **`cli.py`**: Handles command-line argument parsing.
*   **`config.py`**: Configuration constants (Severity levels, Header rules).
*   **`scanner/`**:
    *   `scanner_orchestrator.py`: Coordinates the scanning process.
    *   `http_handler.py`: Handles network requests and HTTPS checks.
    *   `headers_analyzer.py`: Validates security headers.
    *   `cors_analyzer.py`: Checks CORS policies.
*   **`sessions/`**:
    *   `session_logger.py`: Manages saving/loading scan history (JSON).
*   **`report/`**:
    *   `report_formatter.py`: Generates CLI, JSON, and Markdown reports.
*   **`models.py`**: Data structures (`Finding`, `ScanResult`).

---

## ⚠️ Disclaimer & Ethical Use

**This tool is for EDUCATIONAL PURPOSES ONLY.**

*   **No Exploitation:** This tool **does not** perform SQL Injection, XSS, Brute-force, or any active attacks.
*   **Passive Only:** It only reads headers and public configurations sent voluntarily by the server.
*   **Responsibility:** The authors are not responsible for any misuse of this tool. Always ensure you have permission to analyze the target.

---

## 👥 Contributors

| # | Name | GitHub | Role |
|---|---|---|---|
| 1 | Ahmed Alhomili | @ahmedalhomili | Project Lead |
| 2 | Bazil Adel | @bazilb402-dot | HTTP & Network |
| 3 | Othman | @othmancoc | Security Headers |
| 4 | Wazeer Abdulqawi | @wazeercs | CORS & Reporting |
| - | Hafed (Removed) | - | - |
