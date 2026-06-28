import xml.etree.ElementTree as ET
import logging
import re

logger = logging.getLogger(__name__)

def strip_html_tags(text):
    if not text:
        return ""
    clean = re.compile('<.*?>')
    return re.sub(clean, '', text)

def parse_burp(file_path: str) -> list[dict]:
    """
    Parses a Burp Suite XML export file and extracts vulnerability findings.
    
    Returns a list of dictionaries with extracted information.
    """
    findings_map = {}
    
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        if root.tag != 'issues':
            raise ValueError("Invalid Burp XML root element (expected 'issues')")
            
        for issue in root.findall('issue'):
            name_el = issue.find('name')
            title = name_el.text if name_el is not None else 'Unknown Issue'
            
            sev_el = issue.find('severity')
            severity_val = sev_el.text if sev_el is not None else 'Information'
            
            # Map Burp severity to Kairos severity
            severity_map = {
                'Information': 'Info',
                'Low': 'Low',
                'Medium': 'Medium',
                'High': 'High',
                'Critical': 'Critical'
            }
            severity = severity_map.get(severity_val, 'Info')
            
            host_el = issue.find('host')
            host = host_el.text if host_el is not None else ''
            
            path_el = issue.find('path')
            path = path_el.text if path_el is not None else ''
            
            desc_parts = []
            bg_el = issue.find('issueBackground')
            if bg_el is not None and bg_el.text:
                desc_parts.append(strip_html_tags(bg_el.text).strip())
                
            det_el = issue.find('issueDetail')
            if det_el is not None and det_el.text:
                desc_parts.append(strip_html_tags(det_el.text).strip())
                
            description = "\n\n".join(desc_parts)
            
            rem_parts = []
            rbg_el = issue.find('remediationBackground')
            if rbg_el is not None and rbg_el.text:
                rem_parts.append(strip_html_tags(rbg_el.text).strip())
                
            rdet_el = issue.find('remediationDetail')
            if rdet_el is not None and rdet_el.text:
                rem_parts.append(strip_html_tags(rdet_el.text).strip())
                
            remediation = "\n\n".join(rem_parts)
            
            asset_str = f"{host}{path}" if path else host
            if not asset_str:
                asset_str = "Unknown Asset"
                
            if title not in findings_map:
                findings_map[title] = {
                    'title': title,
                    'severity': severity,
                    'description': description,
                    'remediation': remediation,
                    'cvss': 0.0,
                    'assets': [asset_str]
                }
            else:
                if asset_str not in findings_map[title]['assets']:
                    findings_map[title]['assets'].append(asset_str)
                    
        findings = []
        for title, data in findings_map.items():
            assets = data['assets']
            if len(assets) > 1:
                final_host = "Multiple Assets"
                final_path = "Multiple Paths"
                asset_list = "\n".join([f"- {a}" for a in assets])
                final_desc = f"**Affected Assets:**\n{asset_list}\n\n{data['description']}"
            else:
                final_host = assets[0]
                final_path = ""
                final_desc = data['description']
                
            findings.append({
                'host': final_host,
                'path': final_path,
                'title': data['title'],
                'severity': data['severity'],
                'description': final_desc,
                'remediation': data['remediation'],
                'cvss': data['cvss']
            })
            
    except ET.ParseError as e:
        logger.error(f"Error parsing Burp file {file_path}: {e}")
        raise ValueError("Provided file is not a valid XML file.")
    except Exception as e:
        logger.error(f"Unexpected error parsing {file_path}: {e}")
        raise
        
    return findings
