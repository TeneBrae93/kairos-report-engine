# Kairos Report Engine

**This application is currently in early development (prototype stage).**
A formal security assessment is still ongoing. You should only run this application locally or on a trusted, secure network. **It MUST NOT be exposed to the public internet.**

## Kairos Report Engine
Kairos Report Engine is a web application designed to streamline penetration testing project management, vulnerability tracking, and automated report generation. 

It provides a centralized dashboard to track clients, manage projects across various service types (e.g., Web Application, Internal Network, Cloud), maintain a global vulnerability library, and automatically generate professional, well-formatted PDF reports and Attestation Letters.

#### Note from Tyler
I actively use this for engagements at Kairos Sec. Expect regular updates and new features. If you have any ideas, open an "Issue" with a feature request and I'll work on adding it. 

## Key Features

- **PDF Generation**: Export highly customized, professional PDF reports and formal Attestation Letters powered by Jinja2 and WeasyPrint.

- **Rich Text Editor**: Utilize a built-in rich text editor for writing comprehensive "Steps to Reproduce" and embedding proof-of-concept images.
- **Finding Imports**: Seamlessly parse and import scanner outputs from Nessus (.nessus) and Burp Suite (XML).
- **Secure Authentication**: Built-in User Management, Passphrase Hashing (Argon2), and Multi-Factor Authentication (TOTP via Google Authenticator/Authy).
- **Vulnerability Library**: Maintain a global library of common vulnerabilities with support for bulk CSV import/export.
- **Production Ready**: Ships with a utility to generate SSL certificates and runs securely on HTTPS port 443 with Streamlit telemetry and dev tools disabled.

## Prerequisites

Ensure you have the following installed on your system:
- Python 3.10 or higher
- System dependencies for WeasyPrint (e.g., `pango`, `cairo`, `libffi`). 
  - On Ubuntu/Debian: `sudo apt-get install build-essential python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info`
  - On macOS: `brew install pango cairo libffi`
- `openssl` for generating self-signed certificates.

## Docker (Recommended)

The easiest way to run the application. Docker handles all system dependencies (WeasyPrint, Pango, Cairo, etc.) automatically.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) installed

### Quick Start with Docker Compose

```bash
git clone https://github.com/TeneBrae93/kairos-report-engine.git
cd kairos-report-engine
docker compose up -d
```

The application will be available at: **https://localhost:8443**

On first launch, self-signed SSL certificates are generated automatically. Your browser will show a security warning for the self-signed certificate — you can safely bypass it for local use.

### Data Persistence

Three named Docker volumes keep your data safe across container restarts:

| Volume | Contents |
|---|---|
| `kairos-data` | SQLite database (`kairos.db`) |
| `kairos-reports` | Generated PDF reports |
| `kairos-certs` | SSL certificates |

### Useful Commands

```bash
# Stream logs in real time
docker compose logs -f

# Stop the container
docker compose down

# Stop and remove all volumes (Warning: this deletes all data)
docker compose down -v

# Rebuild the image after code changes
docker compose up -d --build
```

### Using Your Own SSL Certificates

You can inject your own certificates into the volume before starting the container:

```bash
docker volume create kairos-certs
docker run --rm -v kairos-certs:/certs -v $(pwd)/my-certs:/src alpine \
    sh -c "cp /src/cert.pem /certs/cert.pem && cp /src/key.pem /certs/key.pem"
docker compose up -d
```

---

## Quick Start (ohne Docker)

To quickly set up and launch the application from scratch, you can copy and paste this entire block into your terminal (assuming you have the prerequisites installed):

```bash
git clone https://github.com/TeneBrae93/kairos-report-engine.git
cd kairos-report-engine
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
chmod +x generate_cert.sh
./generate_cert.sh
sudo .venv/bin/streamlit run --server.port 443 --server.headless true --server.sslCertFile certs/cert.pem --server.sslKeyFile certs/key.pem app.py
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
sudo .venv/bin/streamlit run --server.port 443 --server.headless true --server.sslCertFile certs/cert.pem --server.sslKeyFile certs/key.pem app.py
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
