import requests
import json
import logging

logger = logging.getLogger(__name__)

def enhance_finding_with_ai(finding_data: dict, api_key: str) -> dict:
    """
    Sends the raw finding data to Google Gemini REST API to enhance it with professional 
    descriptions, remediations, PoC, and CVSSv4.
    """
    if not api_key:
        return finding_data
        
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key={api_key}"
    
    prompt = f"""
You are an expert, highly experienced penetration tester. You are reviewing raw vulnerability scanner output and need to convert it into a professional, human-written finding for a client report.

Raw Finding Data:
Title: {finding_data.get('title')}
Severity: {finding_data.get('severity')}
Description: {finding_data.get('description')}
Remediation: {finding_data.get('remediation')}

Tasks:
1. Write a professional description explaining the vulnerability, how it works, and the realistic risk it poses to the organization. Make it sound like it was written by an expert pentester, avoiding robotic language. Use proper Markdown formatting (paragraphs separated by blank lines).
2. Write a professional remediation strategy with actionable, step-by-step advice. YOU MUST format the steps using a proper Markdown numbered list with newlines separating each step (do not mush them into a single paragraph).
3. Provide exactly ONE highly reliable and relevant reference URL that helps with remediation (e.g., OWASP, official vendor docs).
4. Provide a clear Proof-of-Concept (PoC) that is easy for a security team to reproduce (e.g., using a simple curl command, nmap, or python script). Format it beautifully in markdown.
5. Estimate the CVSSv4 Base Score and the corresponding CVSSv4 Vector String based on the finding details.

Output the result STRICTLY as a JSON object matching the schema below. Do not include markdown codeblocks (like ```json), just output the raw JSON.
{{
    "description": "...",
    "remediation": "...",
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
        
        # Merge back with original finding
        finding_data['description'] = enhanced_data.get('description', finding_data['description'])
        finding_data['remediation'] = enhanced_data.get('remediation', finding_data['remediation'])
        finding_data['cvss'] = float(enhanced_data.get('cvss_score', finding_data.get('cvss', 0.0)))
        finding_data['cvss_vector'] = enhanced_data.get('cvss_vector', finding_data.get('cvss_vector', ''))
        finding_data['refs'] = enhanced_data.get('references', finding_data.get('refs', ''))
        
        # Ensure POC is appended or stored
        poc = enhanced_data.get('poc', '')
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
