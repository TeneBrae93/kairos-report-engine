# Kairos Report Engine

Kairos Report Engine is a web application designed to streamline penetration testing project management, vulnerability tracking, and automated report generation. 

It provides a centralized dashboard to track clients, manage projects across various service types (e.g., Web Application, Internal Network, Cloud), maintain a global vulnerability library, and automatically generate professional, well-formatted PDF reports and Attestation Letters.

## Key Features

- **Project Management**: Create and manage clients and penetration testing projects. Contextually switch between clients and pick up where you left off.
- **Secure Authentication**: Built-in User Management, Passphrase Hashing (Argon2), and Multi-Factor Authentication (TOTP via Google Authenticator/Authy).
- **Dynamic Methodologies**: Automatically injects tailored methodologies and boilerplates based on the selected project type.
- **Vulnerability Library**: Maintain a global library of common vulnerabilities with support for bulk CSV import/export.
- **Finding Imports**: Seamlessly parse and import scanner outputs from Nessus (.nessus) and Burp Suite (XML).
- **Rich Text Editor**: Utilize a built-in rich text editor for writing comprehensive "Steps to Reproduce" and embedding proof-of-concept images.
- **PDF Generation**: Export highly customized, professional PDF reports and formal Attestation Letters powered by Jinja2 and WeasyPrint.
- **Production Ready**: Ships with a utility to generate SSL certificates and runs securely on HTTPS port 443 with Streamlit telemetry and dev tools disabled.

## Prerequisites

Ensure you have the following installed on your system:
- Python 3.10 or higher
- System dependencies for WeasyPrint (e.g., `pango`, `cairo`, `libffi`). 
  - On Ubuntu/Debian: `sudo apt-get install build-essential python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info`
  - On macOS: `brew install pango cairo libffi`
- `openssl` for generating self-signed certificates.

## Quick Start

To quickly set up and launch the application from scratch, you can copy and paste this entire block into your terminal (assuming you have the prerequisites installed):

```bash
git clone https://github.com/TeneBrae93/kairos-report-engine.git
cd kairos-report-engine
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
chmod +x generate_cert.sh
./generate_cert.sh
sudo .venv/bin/streamlit run app.py --server.port 443 --server.headless true --server.sslCertFile certs/cert.pem --server.sslKeyFile certs/key.pem
```

## Installation

1. Clone the repository to your local machine.
2. Navigate to the project directory.
3. Create and activate a Python virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
4. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### 1. Generate SSL Certificates
To run the application securely via HTTPS, first generate your self-signed certificates:
```bash
chmod +x generate_cert.sh
./generate_cert.sh
```

### 2. Start the Application
Because the application bounds to port 443 (a privileged port), start the server with `sudo`:
```bash
sudo .venv/bin/streamlit run app.py --server.port 443 --server.headless true --server.sslCertFile certs/cert.pem --server.sslKeyFile certs/key.pem
```

This will start the local Streamlit server. Navigate your web browser to `https://localhost` to access the application. On your first launch, you will be prompted to create the initial Administrator account.

## Directory Structure

- `app.py`: The lightweight Streamlit router and application entry point.
- `views/`: Modularized Python files containing the UI logic for every page in the application.
- `utils/`: Shared utilities, including authentication singletons and image processing helpers.
- `database/`: Contains SQLite database initialization (`db.py`) and CRUD operations (`operations.py`).
- `parsers/`: Contains parsing scripts for integrating external scanner outputs (e.g., Nessus, Burp Suite).
- `reporting/`: Contains the PDF generation engine (`generator.py`) utilizing WeasyPrint.
- `templates/`: Contains HTML/Markdown templates used for styling and formatting the generated PDF reports.
- `data/`: The default directory where the SQLite database (`kairos.db`) and temporary files are stored.
- `reports/`: The default directory where generated PDF reports are saved.
- `certs/`: Directory containing your SSL certificates for HTTPS access.
- `.streamlit/`: Contains the configuration file to enforce port 443 and disable Streamlit analytics.

## Database Note

The application uses a local SQLite database (`data/kairos.db`). On the first run, the database and necessary tables will be created automatically.

## License

This project is released under a custom **Non-Commercial Share-Alike License**. 

In summary:
- You are completely free to use, modify, and distribute the code.
- You **cannot** use this code for the purpose of re-selling or hosting it as a paid commercial service.
- It **must** remain completely open source, and any derivative works must also be released under these exact same terms.

See the [LICENSE](LICENSE) file for the full terms.
