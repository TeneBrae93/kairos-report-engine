import xml.etree.ElementTree as ET
import logging

logger = logging.getLogger(__name__)

def parse_nessus(file_path: str) -> list[dict]:
    """
    Parses a .nessus XML file and extracts vulnerability findings.
    
    Returns a list of dictionaries with extracted information.
    """
    findings = []
    
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Iterate over all report hosts
        for report_host in root.findall('.//ReportHost'):
            host = report_host.attrib.get('name', 'Unknown Host')
            
            # Find all report items (vulnerabilities) for this host
            for item in report_host.findall('ReportItem'):
                severity_val = item.attrib.get('severity', '0')
                
                # We usually ignore severity 0 (Info) for vulnerabilities,
                # but we can let the user filter it in the UI. We'll parse all.
                severity_map = {
                    '0': 'Info',
                    '1': 'Low',
                    '2': 'Medium',
                    '3': 'High',
                    '4': 'Critical'
                }
                severity = severity_map.get(severity_val, 'Unknown')
                
                title = item.attrib.get('pluginName', 'Unknown Plugin')
                
                # Fetch text nodes
                desc_el = item.find('description')
                description = desc_el.text if desc_el is not None else ''
                
                sol_el = item.find('solution')
                remediation = sol_el.text if sol_el is not None else ''
                
                cvss_el = item.find('cvss_base_score')
                try:
                    cvss = float(cvss_el.text) if cvss_el is not None and cvss_el.text else 0.0
                except ValueError:
                    cvss = 0.0
                    
                finding = {
                    'host': host,
                    'title': title,
                    'severity': severity,
                    'description': description,
                    'remediation': remediation,
                    'cvss': cvss,
                }
                findings.append(finding)
                
    except ET.ParseError as e:
        logger.error(f"Error parsing Nessus file {file_path}: {e}")
        raise ValueError("Provided file is not a valid XML/Nessus file.")
    except Exception as e:
        logger.error(f"Unexpected error parsing {file_path}: {e}")
        raise
        
    return findings
