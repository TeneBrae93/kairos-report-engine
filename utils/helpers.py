import os
import uuid
import re
import base64

def get_image_base64(path):
    with open(path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode()

def process_base64_images(html_content, client_id, project_id):
    if not html_content:
        return html_content
    
    pattern = re.compile(r'src="data:image/([^;]+);base64,([^"]+)"')
    
    def replacer(match):
        ext = match.group(1)
        b64_data = match.group(2)
        
        asset_dir = f"data/projects/{client_id}/{project_id}/assets"
        os.makedirs(asset_dir, exist_ok=True)
        
        filename = f"{uuid.uuid4().hex}.{ext}"
        filepath = os.path.join(asset_dir, filename)
        
        try:
            with open(filepath, "wb") as fh:
                fh.write(base64.b64decode(b64_data))
            abs_path = os.path.abspath(filepath)
            return f'src="file://{abs_path}"'
        except Exception as e:
            return match.group(0)
            
    return pattern.sub(replacer, html_content)
