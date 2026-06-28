import os
import markdown
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
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
        md_template_path = os.path.join(template_dir, 'report_template.md')
        
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
            
            finding['steps_html'] = markdown.markdown(finding.get('steps_to_reproduce') or '', extensions=['fenced_code', 'tables', 'md_in_html', 'toc', 'attr_list'])

        table_html = '<table style="width: 100%; border-collapse: collapse; border: 1px solid #333;">\n'
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
                
            import re
            title_slug = re.sub(r'[^a-z0-9]+', '-', finding["title"].lower()).strip('-')
            title_html = f'<a href="#{title_slug}" style="color: #6b46c1; text-decoration: underline;">{finding["title"]}</a>'
            
            table_html += f'    <tr>\n'
            table_html += f'      <td style="border: 1px solid #333; padding: 10px; text-align: center; background-color: white;">{title_html}</td>\n'
            table_html += f'      <td style="border: 1px solid #333; padding: 10px; background-color: {bg_color}; color: white; font-weight: bold; text-align: center;">{sev}</td>\n'
            table_html += f'      <td style="border: 1px solid #333; padding: 10px; text-align: center; color: #fff; background-color: #2c3e50;">{host_html}</td>\n'
            table_html += f'    </tr>\n'
            
        table_html += '  </tbody>\n</table>'
        
        md_content = md_content.replace('{{ findings.table }}', table_html)
        
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

### <a name="{{ finding.title | lower | replace(' ', '-') | replace('(', '') | replace(')', '') }}"></a>{{ finding.title }}

<div style="margin-bottom: 10px;">
    <span class="severity-badge {{ finding.severity }}">{{ finding.severity }}</span>
    {% if finding.cvss > 0 %}&nbsp; <strong>CVSS:</strong> {{ finding.cvss }}{% endif %}
</div>

{% if finding.cvss_vector %}**CVSSv4 Vector String:** {{ finding.cvss_vector }}<br>
{% endif %}
{% if finding.host %}**Affected Host:** {{ finding.host }}<br>
{% endif %}
{% if finding.path %}**Affected Path:** {{ finding.path }}<br>
{% endif %}

<div style="page-break-after: avoid; font-weight: bold; margin-bottom: 10px; margin-top: 20px;">Description:</div>

{{ finding.description }}

{% if finding.steps_to_reproduce %}
<div style="page-break-after: avoid; font-weight: bold; margin-bottom: 10px; margin-top: 20px;">Steps to Reproduce:</div>

<div class="markdown-content">{{ finding.steps_html | safe }}</div>
{% endif %}

<div style="page-break-after: avoid; font-weight: bold; margin-bottom: 10px; margin-top: 20px;">Remediation:</div>

{{ finding.remediation }}

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
        env = Environment()
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
        
        import json
        tools_str = project.get('tools_used', '[]')
        try:
            tools_list = json.loads(tools_str)
            if tools_list and isinstance(tools_list, list):
                tools_html = "<table class=\"tools-table\">\n<tr><th>Tool</th><th>Description</th></tr>\n"
                for t in tools_list:
                    name = t.get('Name', '')
                    desc = t.get('Description', '').replace('\n', '<br>')
                    tools_html += f"<tr><td>{name}</td><td>{desc}</td></tr>\n"
                tools_html += "</table>"
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
            findings=findings
        )
        
        # Convert generated markdown into HTML
        report_html_body = markdown.markdown(rendered_md, extensions=['fenced_code', 'tables', 'md_in_html', 'toc', 'attr_list'])
        
        # Load the HTML wrapper
        html_env = Environment(loader=FileSystemLoader(template_dir))
        html_template = html_env.get_template('report_template.html')
        final_html = html_template.render(body=report_html_body, firm=firm_dict, project=project, client=client)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        project_root = os.path.dirname(os.path.dirname(__file__))
        HTML(string=final_html, base_url=project_root).write_pdf(output_path)
        
        logger.info(f"Successfully generated PDF report at {output_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        raise
