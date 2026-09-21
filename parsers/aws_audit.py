import json
import logging
import markdown

logger = logging.getLogger(__name__)

def parse_aws_audit(file_path: str) -> list[dict]:
    """
    Parses an aws-audit JSON file and extracts vulnerability findings.
    
    Returns a list of dictionaries with extracted information.
    """
    findings = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        if not isinstance(data, list):
            logger.error(f"Expected a list of findings in {file_path}, got {type(data)}.")
            raise ValueError("Provided file is not a valid aws-audit JSON format.")
            
        for item in data:
            title = item.get('target', 'Unknown Finding')
            
            # Map Warning to Informational
            status = item.get('status', '')
            severity = item.get('severity', 'Info')
            if status.lower() == 'warning':
                severity = 'Informational'
                
            description = item.get('details', '')
            
            affected = item.get('affected_resources', [])
            parsed_resources = []
            
            if isinstance(affected, list):
                for res in affected:
                    parts = res.strip().split(' ', 1)
                    if len(parts) == 2:
                        parsed_resources.append({"account_id": parts[0], "resource": parts[1]})
                    else:
                        parsed_resources.append({"account_id": "Unknown", "resource": res})
            else:
                res_str = str(affected)
                parts = res_str.strip().split(' ', 1)
                if len(parts) == 2:
                    parsed_resources.append({"account_id": parts[0], "resource": parts[1]})
                else:
                    parsed_resources.append({"account_id": "Unknown", "resource": res_str})
                    
            host_json = json.dumps(parsed_resources)
            
            # Use 'category' in steps to reproduce or description if needed
            category = item.get('category', '')
            if category:
                description = f"**Category:** {category}\n\n{description}"
                
            findings.append({
                'title': title,
                'severity': severity,
                'description': description,
                'remediation': '',
                'cvss': 0.0,
                'cvss_vector': '',
                'host': host_json,
                'path': '',
                'refs': '',
                'steps_to_reproduce': ''
            })
                
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing aws-audit JSON file {file_path}: {e}")
        raise ValueError("Provided file is not a valid JSON file.")
    except Exception as e:
        logger.error(f"Unexpected error parsing {file_path}: {e}")
        raise
        
    return findings
