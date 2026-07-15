import os
import re
import markdown
from jinja2 import Environment, FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment
from weasyprint import HTML
from urllib.parse import urlparse, unquote
from weasyprint import default_url_fetcher


def _safe_url_fetcher(allowed_root):
    """Restrict WeasyPrint resource loading: allow only data: URIs and local files
    under `allowed_root` (the app's own data dir, for charts/assets). Blocks all
    http/https (SSRF) and any file:// outside the data dir (LFI) — covering CSS
    url()/@import/<link> vectors a src="file://" regex misses."""
    allowed_root = os.path.realpath(allowed_root)

    def _fetch(url, *args, **kwargs):
        if url.startswith("data:"):
            return default_url_fetcher(url, *args, **kwargs)
        parsed = urlparse(url)
        if parsed.scheme in ("http", "https", "ftp"):
            raise ValueError(f"Blocked remote resource during report render (SSRF): {url[:100]}")
        if parsed.scheme in ("file", ""):
            path = os.path.realpath(unquote(parsed.path))
            if path == allowed_root or path.startswith(allowed_root + os.sep):
                return default_url_fetcher(url, *args, **kwargs)
            raise ValueError(f"Blocked local file outside data dir (LFI): {url[:100]}")
        raise ValueError(f"Blocked URL scheme during report render: {parsed.scheme}")

    return _fetch
import logging

from datetime import datetime

logger = logging.getLogger(__name__)

def format_date_with_suffix(date_str):
    if not date_str:
        return ""
    try:
        dt = datetime.strptime(date_str, '%Y-%m-%d')
        day = dt.day
        if 11 <= day <= 13:
            suffix = 'th'
        else:
            suffix = {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
        return dt.strftime(f'%B {day}{suffix}, %Y')
    except Exception:
        return date_str

def generate_report(project, client, firm, findings, output_path):
    """
    Generates a PDF report from Jinja2 template + WeasyPrint.
    Uses report_template.md as the source, dynamically injecting findings.
    """
    try:
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
        
        safe_type = project.get('project_type', '').replace(' ', '_').replace('/', '_')
        custom_template_path = os.path.join(template_dir, f'report_template_{safe_type}.md')
        default_template_path = os.path.join(template_dir, 'report_template.md')

        # CWE-22 defense: verify resolved path stays within templates/
        template_root = os.path.realpath(template_dir)
        real_custom = os.path.realpath(custom_template_path)
        if not (real_custom.startswith(template_root + os.sep) or real_custom == template_root):
            raise ValueError("Security error: template path escapes templates/ directory")
        
        if os.path.exists(custom_template_path):
            md_template_path = custom_template_path
        else:
            md_template_path = default_template_path
        
        with open(md_template_path, 'r', encoding='utf-8') as f:
            md_content = f.read()

        project['report_date_formatted'] = format_date_with_suffix(project.get('report_date', ''))
        project['start_date_formatted'] = format_date_with_suffix(project.get('start_date', ''))
        project['end_date_formatted'] = format_date_with_suffix(project.get('end_date', ''))

        severity_rank = {
            'Critical': 1,
            'High': 2,
            'Medium': 3,
            'Low': 4,
            'Informational': 5,
            'Info': 5
        }
        
        # Sort findings from most severe to least severe. In case of ties, CVSS score can be used as a secondary sort.
        findings.sort(key=lambda x: (severity_rank.get(x.get('severity', 'Info'), 99), -float(x.get('cvss') or 0.0)))

        severity_counts = { 'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0 }
        for finding in findings:
            sev = finding.get('severity', 'Info')
            if sev == 'Info': sev = 'Informational'
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts['Informational'] += 1
            
            # Single source of truth for the anchor so the summary-table link
            # and the detailed-findings anchor always match.
            finding['anchor'] = re.sub(r'[^a-z0-9]+', '-', (finding.get('title') or '').lower()).strip('-')
            finding['steps_html'] = markdown.markdown(finding.get('steps_to_reproduce') or '', extensions=['fenced_code', 'tables', 'md_in_html', 'toc', 'attr_list'])

        table_html = '<div style="page-break-inside: avoid; margin-bottom: 20px;">\n'
        table_html += '<table style="width: 100%; border-collapse: collapse; border: 1px solid #333;">\n'
        table_html += '  <thead>\n'
        table_html += '    <tr>\n'
        table_html += '      <th style="border: 1px solid #333; background-color: #555; color: white; padding: 10px; font-weight: bold; width: 40%; text-align: center;">Finding</th>\n'
        table_html += '      <th style="border: 1px solid #333; background-color: #555; color: white; padding: 10px; font-weight: bold; width: 20%; text-align: center;">Risk Rating</th>\n'
        table_html += '      <th style="border: 1px solid #333; background-color: #555; color: white; padding: 10px; font-weight: bold; width: 40%; text-align: center;">Affected Hosts</th>\n'
        table_html += '    </tr>\n'
        table_html += '  </thead>\n'
        table_html += '  <tbody>\n'
        
        color_map = {
            'Critical': '#9b2c2c',
            'High': '#c53030',
            'Medium': '#dd6b20',
            'Low': '#38a169',
            'Informational': '#3182ce'
        }
        
        for finding in findings:
            sev = finding.get('severity', 'Info')
            if sev == 'Info': sev = 'Informational'
            bg_color = color_map.get(sev, '#555')
            
            host = finding.get('host', '')
            host_display = host if host else 'N/A'
            if host_display.startswith('http'):
                host_html = f'<a href="{host_display}" style="color: #fff; text-decoration: underline;">{host_display}</a>'
            else:
                host_html = host_display
                
            title_slug = finding['anchor']
            title_html = f'<a href="#{title_slug}" style="color: #6b46c1; text-decoration: underline;">{finding["title"]}</a>'
            
            table_html += f'    <tr>\n'
            table_html += f'      <td style="border: 1px solid #333; padding: 10px; text-align: center; background-color: white;">{title_html}</td>\n'
            table_html += f'      <td style="border: 1px solid #333; padding: 10px; background-color: {bg_color}; color: white; font-weight: bold; text-align: center;">{sev}</td>\n'
            table_html += f'      <td style="border: 1px solid #333; padding: 10px; text-align: center; color: #fff; background-color: #2c3e50;">{host_html}</td>\n'
            table_html += f'    </tr>\n'
            
        table_html += '  </tbody>\n</table>\n</div>'
        
        md_content = md_content.replace('{{ findings.table }}', '{{ findings_table }}')
        
        # --- Findings Bar Chart ---
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import uuid
        
        labels = ['Critical', 'High', 'Medium', 'Low', 'Informational']
        counts = [severity_counts.get(sev, 0) for sev in labels]
        
        max_count = max(counts) if counts else 0
        if max_count <= 7:
            y_max = 7
            y_step = 1
        else:
            y_max = max_count + (5 - (max_count % 5)) if max_count % 5 != 0 else max_count
            y_step = max(1, y_max // 5)
            
        fig, ax = plt.subplots(figsize=(7, 4))
        colors = ['#c00000', '#ff0000', '#ff9933', '#ffcc00', '#99cc00']
        bars = ax.bar(labels, counts, color=colors, width=0.5)
        
        ax.set_title('Findings in this Report by Risk Rating', fontsize=16, fontweight='bold', pad=20)
        ax.set_ylim(0, y_max)
        ax.set_yticks(list(range(0, y_max + 1, y_step)))
        
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['bottom'].set_color('#333')
        ax.spines['left'].set_color('#333')
        
        for bar in bars:
            yval = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2.0, yval + (y_max * 0.02), int(yval), ha='center', va='bottom', fontweight='bold', fontsize=12)
            
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        chart_filename = f"chart_{uuid.uuid4().hex}.png"
        chart_path = os.path.join(os.path.dirname(output_path), chart_filename)
        
        plt.tight_layout()
        plt.savefig(chart_path, dpi=150)
        plt.close(fig)
        
        chart_html = f'<div style="text-align: center; margin: 40px 0; page-break-inside: avoid;"><img src="file://{os.path.abspath(chart_path)}" style="max-width: 600px; width: 100%;"></div>'
        project['findings_chart'] = chart_html
        
        detailed_findings_md = """
{% for finding in findings %}
{% if not loop.first %}
<div style="page-break-before: always;"></div>
{% endif %}

<div style="page-break-inside: avoid;" markdown="1">
### <a name="{{ finding.anchor }}"></a>{{ finding.title }}

<div style="margin-bottom: 10px;">
    <span class="severity-badge {{ finding.severity }}">{{ finding.severity }}</span>
    {% if finding.cvss and finding.cvss > 0 %}&nbsp; <strong>CVSS:</strong> {{ finding.cvss }}{% endif %}
</div>

{% if finding.cvss_vector %}**CVSSv4 Vector String:** {{ finding.cvss_vector }}<br>
{% endif %}
{% if finding.host %}**Affected Host:** {{ finding.host }}<br>
{% endif %}
{% if finding.path %}**Affected Path:** {{ finding.path }}<br>
{% endif %}

<div style="page-break-after: avoid; font-weight: bold; margin-bottom: 10px; margin-top: 20px;">Description:</div>
</div>

{{ finding.description }}

<div style="page-break-after: avoid; font-weight: bold; margin-bottom: 10px; margin-top: 20px;">Remediation:</div>

{{ finding.remediation }}

{% if finding.steps_to_reproduce %}
<div style="page-break-after: avoid; font-weight: bold; margin-bottom: 10px; margin-top: 20px;">Steps to Reproduce:</div>

<div class="markdown-content">{{ finding.steps_html | safe }}</div>
{% endif %}

{% if finding.refs %}
<div style="page-break-after: avoid; font-weight: bold; margin-bottom: 10px; margin-top: 20px;">References:</div>

{% for ref in finding.refs.splitlines() %}
{% if ref.strip() %}
- <a href="{{ ref.strip() }}" target="_blank" style="word-break: break-all;">{{ ref.strip() }}</a>
{% endif %}
{% endfor %}
{% endif %}

{% endfor %}
"""
        # Inject where user explicitly requested
        md_content = md_content.replace('{{ findings.detailed_findings }}', detailed_findings_md)
        env = SandboxedEnvironment()  # sandbox blocks dunder/globals access even for user-edited templates
        template = env.from_string(md_content)
        
        firm_dict = dict(firm)
        firm_dict['summary_of_strengths'] = project.get('summary_of_strengths', firm_dict.get('summary_of_strengths', ''))
        firm_dict['summary_of_weaknesses'] = project.get('summary_of_weaknesses', firm_dict.get('summary_of_weaknesses', ''))
        firm_dict['cvss_mapping'] = project.get('cvss_mapping', firm_dict.get('cvss_mapping', ''))
        firm_dict['tools_used'] = project.get('tools_used', firm_dict.get('tools_used', ''))
        
        tester = {
            'name': project.get('tester_name', ''),
            'description': project.get('tester_description', '')
        }
        
        from database import operations as db
        for t in db.get_testers():
            if t['name'] == tester['name']:
                tester['description'] = t['bio']
                break
        
        import json
        tools_str = project.get('tools_used', '[]')
        try:
            tools_list = json.loads(tools_str)
            if tools_list and isinstance(tools_list, list):
                tools_html = "<div style=\"page-break-inside: avoid;\">\n<table class=\"tools-table\">\n<tr><th>Tool</th><th>Description</th></tr>\n"
                for t in tools_list:
                    name = t.get('Name', '')
                    desc = t.get('Description', '').replace('\n', '<br>')
                    tools_html += f"<tr><td>{name}</td><td>{desc}</td></tr>\n"
                tools_html += "</table>\n</div>"
                project['tools_used_table'] = tools_html
            else:
                project['tools_used_table'] = tools_str.replace('\n', '<br>')
        except Exception:
            project['tools_used_table'] = tools_str.replace('\n', '<br>')
            
        rendered_md = template.render(
            project=project,
            client=client,
            firm=firm_dict,
            tester=tester,
            findings=findings,
            findings_table=table_html
        )
        
        # Convert generated markdown into HTML
        report_html_body = markdown.markdown(rendered_md, extensions=['fenced_code', 'tables', 'md_in_html', 'toc', 'attr_list'])
        
        # Load the HTML wrapper
        html_env = Environment(loader=FileSystemLoader(template_dir))
        html_template = html_env.get_template('report_template.html')
        final_html = html_template.render(body=report_html_body, firm=firm_dict, project=project, client=client)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        project_root = os.path.dirname(os.path.dirname(__file__))
        _fetcher = _safe_url_fetcher(os.path.join(project_root, "data"))
        HTML(string=final_html, base_url=project_root, url_fetcher=_fetcher).write_pdf(output_path)
        
        logger.info(f"Successfully generated PDF report at {output_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        raise

def generate_attestation(project, client, firm, output_path, custom_bio=None):
    """
    Generates an Attestation Letter PDF.
    """
    try:
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
        md_template_path = os.path.join(template_dir, 'attestation_template.md')

        # CWE-22 defense: verify resolved path stays within templates/
        template_root = os.path.realpath(template_dir)
        real_path = os.path.realpath(md_template_path)
        if not (real_path.startswith(template_root + os.sep) or real_path == template_root):
            raise ValueError("Security error: template path escapes templates/ directory")
        
        with open(md_template_path, 'r', encoding='utf-8') as f:
            md_content = f.read()

        project['report_date_formatted'] = format_date_with_suffix(project.get('report_date', ''))
        project['start_date_formatted'] = format_date_with_suffix(project.get('start_date', ''))
        project['end_date_formatted'] = format_date_with_suffix(project.get('end_date', ''))

        firm_dict = {f.get('key'): f.get('value') for f in firm} if isinstance(firm, list) else firm

        from database import operations as db
        tester = {
            'name': project.get('tester_name', ''),
            'description': project.get('tester_description', ''),
            'title': ''
        }
        if tester['name']:
            db_testers = db.get_testers()
            db_tester = next((t for t in db_testers if t['name'] == tester['name']), None)
            if db_tester:
                tester['description'] = custom_bio if custom_bio is not None else db_tester.get('bio', '')
                tester['title'] = db_tester.get('title', '')
                
        env = SandboxedEnvironment()  # sandbox blocks dunder/globals access even for user-edited templates
        template = env.from_string(md_content)
        
        rendered_md = template.render(
            project=project,
            client=client,
            firm=firm_dict,
            tester=tester
        )
        
        report_html_body = markdown.markdown(rendered_md, extensions=['fenced_code', 'tables', 'md_in_html', 'attr_list'])
        
        html_env = Environment(loader=FileSystemLoader(template_dir))
        html_template = html_env.get_template('attestation_wrapper.html')
        project_root = os.path.dirname(os.path.dirname(__file__))
        
        final_html = html_template.render(content=report_html_body, firm=firm_dict, project=project, client=client, base_dir=project_root)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        _fetcher = _safe_url_fetcher(os.path.join(project_root, "data"))
        HTML(string=final_html, base_url=project_root, url_fetcher=_fetcher).write_pdf(output_path)
        
        logger.info(f"Successfully generated Attestation Letter at {output_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to generate attestation: {e}")
        raise
