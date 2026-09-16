import json
import logging
import markdown

logger = logging.getLogger(__name__)

def parse_azure_audit(file_path: str) -> list[dict]:
    """
    Parses an azure-audit JSON file and extracts vulnerability findings.
    
    Returns a list of dictionaries with extracted information.
    """
    findings = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        if not isinstance(data, list):
            logger.error(f"Expected a list of findings in {file_path}, got {type(data)}.")
            raise ValueError("Provided file is not a valid azure-audit JSON format.")
            
        for item in data:
            title = item.get('finding_name', 'Unknown Finding')
            severity = item.get('severity', 'Info')
            description = item.get('details', '')
            
            affected = item.get('affected_resources', [])
            host = ", ".join(affected) if isinstance(affected, list) else str(affected)
            
            verification_cmd = item.get('verification_command', '')
            steps_html = ""
            if verification_cmd:
                raw_markdown = f"**Verification Command**\n\n```bash\n{verification_cmd}\n```"
                steps_html = markdown.markdown(raw_markdown, extensions=['fenced_code', 'tables'])
                
            findings.append({
                'title': title,
                'severity': severity,
                'description': description,
                'remediation': '',
                'cvss': 0.0,
                'cvss_vector': '',
                'host': host,
                'path': '',
                'refs': '',
                'steps_to_reproduce': steps_html
            })
                
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing azure-audit JSON file {file_path}: {e}")
        raise ValueError("Provided file is not a valid JSON file.")
    except Exception as e:
        logger.error(f"Unexpected error parsing {file_path}: {e}")
        raise
        
    return findings
