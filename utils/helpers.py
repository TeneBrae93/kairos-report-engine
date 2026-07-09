import os
import hashlib
import re
import base64

def get_image_base64(path):
    with open(path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode()

def restore_base64_images(html_content):
    if not html_content:
        return html_content
        
    pattern = re.compile(r'src="file://([^"]+)"')
    
    def replacer(match):
        filepath = match.group(1)
        if os.path.exists(filepath):
            ext = filepath.split('.')[-1]
            try:
                b64 = get_image_base64(filepath)
                return f'src="data:image/{ext};base64,{b64}"'
            except Exception:
                pass
        return match.group(0)
        
    return pattern.sub(replacer, html_content)

def process_base64_images(html_content, client_id, project_id):
    if not html_content:
        return html_content
    
    pattern = re.compile(r'src="data:image/([^;]+);base64,([^"]+)"')
    
    def replacer(match):
        ext = match.group(1)
        b64_data = match.group(2)
        
        asset_dir = f"data/projects/{client_id}/{project_id}/assets"
        os.makedirs(asset_dir, exist_ok=True)
        
        # Use MD5 hash of the data so we don't duplicate files on every save
        filename = f"{hashlib.md5(b64_data.encode()).hexdigest()}.{ext}"
        filepath = os.path.join(asset_dir, filename)
        
        try:
            with open(filepath, "wb") as fh:
                fh.write(base64.b64decode(b64_data))
            abs_path = os.path.abspath(filepath)
            return f'src="file://{abs_path}"'
        except Exception as e:
            return match.group(0)
            
    return pattern.sub(replacer, html_content)
