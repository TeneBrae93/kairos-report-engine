import requests
import json
import logging
import re

logger = logging.getLogger(__name__)

class Redactor:
    def __init__(self, client_name: str = ""):
        self.mapping = {}
        self.counters = {
            "IP_ADDRESS": 1,
            "AWS_ACCOUNT": 1,
            "AWS_ARN": 1,
            "AZURE_SUB": 1,
            "CLIENT_NAME": 1
        }
        self.client_name = client_name
        
    def _replace(self, match, category):
        original = match.group(0)
        
        # If we already mapped this exact string, reuse its placeholder
        for placeholder, mapped_val in self.mapping.items():
            if mapped_val == original:
                return placeholder
                
        # Create new placeholder
        placeholder = f"[[{category}_{self.counters[category]}]]"
        self.mapping[placeholder] = original
        self.counters[category] += 1
        return placeholder

    def redact(self, text: str) -> str:
        if not text:
            return text
            
        # Redact Client Name (case-insensitive)
        if self.client_name and len(self.client_name) > 2:
            # Escape regex special chars in client name
            client_regex = re.escape(self.client_name)
            text = re.sub(client_regex, lambda m: self._replace(m, "CLIENT_NAME"), text, flags=re.IGNORECASE)
            
        # Redact IPs (basic IPv4)
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        text = re.sub(ip_pattern, lambda m: self._replace(m, "IP_ADDRESS"), text)
        
        # Redact AWS Account IDs (12 digits, standalone or in a string)
        # Be careful not to match random 12 digit numbers if possible, but for pentest data it's usually safe
        aws_acc_pattern = r'\b\d{12}\b'
        text = re.sub(aws_acc_pattern, lambda m: self._replace(m, "AWS_ACCOUNT"), text)
        
        # Redact AWS ARNs
        arn_pattern = r'arn:aws:[a-zA-Z0-9\-]+:[a-z0-9\-]*:\d{12}:[a-zA-Z0-9\-_\/:\.]+'
        text = re.sub(arn_pattern, lambda m: self._replace(m, "AWS_ARN"), text)
        
        # Redact Azure Subscriptions
        azure_sub_pattern = r'/subscriptions/[0-9a-fA-F\-]{36}'
        text = re.sub(azure_sub_pattern, lambda m: self._replace(m, "AZURE_SUB"), text)
        
        return text
        
    def rehydrate(self, text: str) -> str:
        if not text:
            return text
        # Replace all placeholders with their original values
        for placeholder, original in self.mapping.items():
            text = text.replace(placeholder, original)
        return text

def enhance_finding_with_ai(finding_data: dict, api_key: str, client_name: str = "") -> dict:
    """
    Sends the raw finding data to Google Gemini REST API to enhance it with professional 
    descriptions, remediations, PoC, and CVSSv4. Data is masked before sending.
    """
    if not api_key:
        return finding_data
        
    redactor = Redactor(client_name)
    r_title = redactor.redact(finding_data.get('title') or '')
    r_desc = redactor.redact(finding_data.get('description') or '')
    r_rem = redactor.redact(finding_data.get('remediation') or '')
    r_steps = redactor.redact(finding_data.get('steps_to_reproduce') or '')
        
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key={api_key}"
    
    prompt = f"""
You are an expert, highly experienced penetration tester. You are reviewing raw vulnerability scanner output and need to convert it into a professional, human-written finding for a client report.

Note: Sensitive data (like IPs, account numbers, client names) has been masked with placeholders like [[IP_ADDRESS_1]]. Please leave these placeholders exactly as they are in your output.

Raw Finding Data:
Title: {r_title}
Severity: {finding_data.get('severity')}
Description: {r_desc}
Remediation: {r_rem}
Existing Proof of Concept / Verification Command: {r_steps}

Tasks:
1. Write a professional description explaining the vulnerability, how it works, and the realistic risk it poses to the organization. Make it sound like it was written by an expert pentester, avoiding robotic language. Use proper Markdown formatting (paragraphs separated by blank lines).
2. Write a professional remediation strategy with actionable, step-by-step advice. YOU MUST format the steps using a proper Markdown numbered list with newlines separating each step (do not mush them into a single paragraph).
3. Provide exactly ONE highly reliable and relevant reference URL that helps with remediation (e.g., OWASP, official vendor docs).
4. Provide a clear Proof-of-Concept (PoC) that is easy for a security team to reproduce. If an 'Existing Proof of Concept / Verification Command' is provided above, DO NOT overwrite it. Instead, incorporate it and explain it, or output it alongside any additional context you wish to add. Format it beautifully in markdown.
5. Re-evaluate and calculate the Severity (Critical, High, Medium, Low, Informational) and the CVSSv4 Base Score and Vector String. Assume an "assumed breach" context where layered defenses (like MFA, internal firewalls, etc.) often mitigate the impact. You should drastically downgrade the severity from what automated tooling suggests if it lacks this context. Common architectural/hygiene findings (like 'Public IP Addresses', 'Guest Accounts', 'Short Log Retention') that do not have an immediate exploit path should be aggressively downgraded to 'Informational' or 'Low' so the assessor can review them manually without inflating the report's risk rating.

Output the result STRICTLY as a JSON object matching the schema below. Do not include markdown codeblocks (like ```json), just output the raw JSON.
{{
    "description": "...",
    "remediation": "...",
    "severity": "...",
    "cvss_score": 0.0,
    "cvss_vector": "CVSS:4.0/AV:...",
    "references": "...",
    "poc": "..."
}}
"""

    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "safetySettings": [
            {
                "category": "HARM_CATEGORY_HARASSMENT",
                "threshold": "BLOCK_NONE"
            },
            {
                "category": "HARM_CATEGORY_HATE_SPEECH",
                "threshold": "BLOCK_NONE"
            },
            {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "threshold": "BLOCK_NONE"
            },
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                "threshold": "BLOCK_NONE"
            }
        ],
        "generationConfig": {
            "temperature": 0.3,
            "responseMimeType": "application/json"
        }
    }
    
    headers = {
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        
        data = response.json()
        content = data['candidates'][0]['content']['parts'][0]['text'].strip()
        
        # Clean up markdown if the model ignored our schema instruction
        if content.startswith("```json"):
            content = content[7:]
        elif content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()
        
        enhanced_data = json.loads(content)
        
        # Rehydrate the AI response
        desc = redactor.rehydrate(enhanced_data.get("description", ""))
        rem = redactor.rehydrate(enhanced_data.get("remediation", ""))
        poc = redactor.rehydrate(enhanced_data.get("poc", ""))
        refs = redactor.rehydrate(enhanced_data.get("references", ""))
        
        # Merge back with original finding
        finding_data['description'] = desc if desc else finding_data['description']
        finding_data['remediation'] = rem if rem else finding_data['remediation']
        finding_data['severity'] = enhanced_data.get('severity', finding_data.get('severity', 'Info'))
        finding_data['cvss'] = float(enhanced_data.get('cvss_score', finding_data.get('cvss', 0.0)))
        finding_data['cvss_vector'] = enhanced_data.get('cvss_vector', finding_data.get('cvss_vector', ''))
        finding_data['refs'] = refs if refs else finding_data.get('refs', '')
        
        # Ensure POC is appended or stored
        if poc:
            import markdown
            finding_data['steps_to_reproduce'] = markdown.markdown(poc, extensions=['fenced_code', 'tables'])
            
        return finding_data

    except Exception as e:
        logger.error(f"AI Enhancement failed for finding '{finding_data.get('title')}': {e}")
        with open("ai_error.log", "a") as f:
            f.write(f"Error on {finding_data.get('title')}: {e}\n")
            if 'response' in locals() and hasattr(response, 'text'):
                f.write(f"Response Body: {response.text}\n")
        return finding_data
