# Kairos Report Engine

Kairos Report Engine is a Streamlit-based web application designed to streamline penetration testing project management, vulnerability tracking, and automated report generation. It provides a centralized dashboard to track clients, manage projects across various service types (e.g., Web Application, Internal Network, Cloud), maintain a global vulnerability library, and automatically generate professional, well-formatted PDF reports.

### Important
This is a prototype and there is no authentication built into it. You should only use this locally on a secure network. This should NEVER be exposed to the internet. 

## Key Features

- **Project Management**: Create and manage clients and penetration testing projects.
- **Dynamic Methodologies**: Automatically injects tailored methodologies and boilerplates based on the selected project type.
- **Vulnerability Library**: Maintain a global library of common vulnerabilities with support for bulk CSV import/export.
- **Finding Imports**: Seamlessly parse and import scanner outputs from Nessus (.nessus) and Burp Suite (XML).
- **Rich Text Editor**: Utilize a built-in rich text editor for writing comprehensive "Steps to Reproduce" and embedding proof-of-concept images.
- **PDF Report Generation**: Export highly customized, professional PDF reports powered by Jinja2 and WeasyPrint.

## Prerequisites

Ensure you have the following installed on your system:
- Python 3.10 or higher
- System dependencies for WeasyPrint (e.g., `pango`, `cairo`, `libffi`). 
  - On Ubuntu/Debian: `sudo apt-get install build-essential python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info`
  - On macOS: `brew install pango cairo libffi`

## Installation

1. Clone the repository to your local machine.
2. Navigate to the project directory.
3. (Optional but recommended) Create and activate a Python virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
4. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

To launch the application, run the following command from the root of the project directory:

```bash
streamlit run app.py
```

This will start the local Streamlit server and automatically open the application in your default web browser (typically at `http://localhost:8501`).

## Directory Structure

- `app.py`: The main Streamlit application script.
- `database/`: Contains SQLite database initialization (`db.py`) and CRUD operations (`operations.py`).
- `parsers/`: Contains parsing scripts for integrating external scanner outputs (e.g., Nessus, Burp Suite).
- `reporting/`: Contains the PDF generation engine (`generator.py`) utilizing WeasyPrint.
- `templates/`: Contains HTML/Markdown templates used for styling and formatting the generated PDF reports.
- `data/`: The default directory where the SQLite database (`kairos.db`) and temporary files are stored.
- `reports/`: The default directory where generated PDF reports are saved.

## Database Note

The application uses a local SQLite database (`data/kairos.db`). On the first run, the database and necessary tables will be created automatically.
