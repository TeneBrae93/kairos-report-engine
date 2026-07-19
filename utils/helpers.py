import os
import hashlib
import re
import base64

import nh3

RICH_TEXT_TAGS = {
    'a', 'abbr', 'b', 'blockquote', 'br', 'code', 'del', 'div', 'em',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img', 'li',
    'ol', 'p', 'pre', 's', 'span', 'strong', 'sub', 'sup', 'table',
    'tbody', 'td', 'th', 'thead', 'tr', 'u', 'ul'
}
RICH_TEXT_ATTRIBUTES = {
    '*': {'class', 'title'},
    'a': {'href', 'target', 'title'},
    'img': {'src', 'alt', 'title', 'width', 'height'},
    'ol': {'start', 'type'},
    'li': {'value'},
    'td': {'colspan', 'rowspan'},
    'th': {'colspan', 'rowspan'},
}
RICH_TEXT_URL_SCHEMES = {'data', 'http', 'https', 'mailto'}
RICH_TEXT_DROP_CONTENT = {'embed', 'iframe', 'math', 'object', 'script', 'style', 'svg', 'template'}


def sanitize_rich_html(html_content):
    """Return the supported rich-text subset with executable markup removed."""
    if not html_content:
        return ''
    return nh3.clean(
        html_content,
        tags=RICH_TEXT_TAGS,
        attributes=RICH_TEXT_ATTRIBUTES,
        clean_content_tags=RICH_TEXT_DROP_CONTENT,
        url_schemes=RICH_TEXT_URL_SCHEMES,
        strip_comments=True,
    )


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
