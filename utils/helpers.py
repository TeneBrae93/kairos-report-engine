import os
import hashlib
import re
import base64
import shutil
import tempfile

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


def sanitize_rich_html(html_content: str) -> str:
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


def normalize_code_blocks_for_markdown(html_content: str) -> str:
    """Ensure <pre> blocks start on their own block lines so Python-Markdown preserves multi-line code blocks."""
    if not html_content:
        return ''
    return re.sub(
        r'\s*(<pre\b[^>]*>.*?</pre>)\s*',
        r'\n\n\1\n\n',
        html_content,
        flags=re.DOTALL | re.IGNORECASE,
    )


def _inject_script_into_build_dir(build_dir: str, plugin_js_path: str) -> bool:
    """Copy jodit_codeblock.js into the Streamlit Jodit build dir and link it in index.html."""
    index_path = os.path.join(build_dir, "index.html")
    target_js_path = os.path.join(build_dir, "jodit_codeblock.js")
    if not os.path.exists(index_path) or not os.path.exists(plugin_js_path):
        return False

    with open(plugin_js_path, "rb") as src_f:
        plugin_bytes = src_f.read()
    plugin_hash = hashlib.md5(plugin_bytes).hexdigest()[:8]

    with open(target_js_path, "wb") as dst_f:
        dst_f.write(plugin_bytes)

    with open(index_path, "r", encoding="utf-8") as idx_f:
        html = idx_f.read()

    script_tag = f'<script defer="defer" src="./jodit_codeblock.js?v={plugin_hash}"></script>'
    if "jodit_codeblock.js" in html:
        updated_html = re.sub(
            r'<script[^>]*src="\./jodit_codeblock\.js[^"]*"[^>]*></script>',
            script_tag,
            html,
        )
    else:
        updated_html = html.replace("</head>", f"{script_tag}</head>", 1)

    if updated_html != html:
        with open(index_path, "w", encoding="utf-8") as idx_f:
            idx_f.write(updated_html)
    return True


def ensure_jodit_codeblock_plugin() -> None:
    """Ensure the Streamlit Jodit component includes the custom Code Block toolbar & footer button."""
    plugin_js_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jodit_codeblock.js")
    if not os.path.exists(plugin_js_path):
        return

    try:
        import streamlit_jodit
        import streamlit.components.v1 as components

        pkg_dir = os.path.dirname(os.path.abspath(streamlit_jodit.__file__))
        orig_build_dir = os.path.join(pkg_dir, "frontend", "build")
        if not os.path.exists(orig_build_dir):
            return

        try:
            _inject_script_into_build_dir(orig_build_dir, plugin_js_path)
        except OSError:
            fallback_dir = os.path.join(tempfile.gettempdir(), "kairos_jodit_build")
            if not os.path.exists(fallback_dir):
                shutil.copytree(orig_build_dir, fallback_dir, dirs_exist_ok=True)
            _inject_script_into_build_dir(fallback_dir, plugin_js_path)
            streamlit_jodit._component_func = components.declare_component(
                "streamlit_jodit", path=fallback_dir
            )
    except Exception:
        pass


ensure_jodit_codeblock_plugin()


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
