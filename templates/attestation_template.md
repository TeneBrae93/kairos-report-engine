To Whom It May Concern,

This letter certifies that {{ firm.firm_name }} performed a comprehensive Penetration Test for {{ client.name }}. The assessment was conducted from {{ project.start_date_formatted }} through {{ project.end_date_formatted }}. 

The testing was performed by {{ tester.name }}. {{ tester.description }}

**Scope and Methodology** 
<br>
{% if project.project_type == 'Internal Network Penetration Test' %}
The assessment covered the internal network infrastructure of {{ client.name }}, specifically targeting the following in-scope assets:
{% elif project.project_type == 'Network Vulnerability Scan' %}
The assessment covered the internal network infrastructure of {{ client.name }}, specifically targeting the following in-scope assets:
{% elif project.project_type == 'External Network Penetration Test' %}
The assessment covered the external, public-facing network infrastructure of {{ client.name }}, specifically targeting the following in-scope assets:
{% elif project.project_type == 'AI/LLM Penetration Test' %}
The assessment covered the {{ client.name }} {{ project.application_name }} artificial intelligence model and its integrations, specifically targeting the following in-scope assets:
{% elif project.project_type == 'Cloud Penetration Test' %}
The assessment covered the {{ client.name }} cloud infrastructure and hosted services, specifically targeting the following in-scope assets:
{% else %}
The assessment covered the {{ client.name }} {{ project.application_name }} environment and its associated functionalities, specifically targeting the following in-scope assets:
{% endif %}

{% if project.hosts %}
{% set scope_hosts = project.hosts.split('\n') %}
{% for sh in scope_hosts %}
{% if sh.strip() %}
- {{ sh.strip() }}
{% endif %}
{% endfor %}
{% endif %}

{% if project.project_type == 'Internal Network Penetration Test' %}
The assessment followed a comprehensive methodology based on industry-recognized standards, including the Penetration Testing Execution Standard (PTES), tailored specifically to the internal environment.

**Conclusion**
<br>
Based on the testing performed, {{ firm.firm_name }} confirms that {{ client.name }} has subjected its internal network to a rigorous security assessment. The organization has demonstrated a strong commitment to security by engaging in proactive testing and maintaining robust foundational controls.

{% elif project.project_type == 'Network Vulnerability Scan' %}
The assessment followed a structured methodology based on industry-recognized standards, such as the NIST Cybersecurity Framework and OWASP. Unlike a penetration test, this assessment focused on surface-area coverage and risk identification rather than active exploitation.

**Conclusion**
<br>
Based on the testing performed, {{ firm.firm_name }} confirms that {{ client.name }} has subjected its internal network to a rigorous vulnerability assessment. The organization has demonstrated a strong commitment to security by engaging in proactive scanning and maintaining robust foundational controls.

{% elif project.project_type == 'External Network Penetration Test' %}
The assessment followed a comprehensive methodology based on industry-recognized standards, including the Penetration Testing Execution Standard (PTES), tailored specifically to the external attack surface.

**Conclusion**
<br>
Based on the testing performed, {{ firm.firm_name }} confirms that {{ client.name }} has subjected its external network to a rigorous security assessment. The organization has demonstrated a strong commitment to security by engaging in proactive testing and maintaining robust foundational controls.

{% elif project.project_type == 'AI/LLM Penetration Test' %}
The assessment followed a comprehensive methodology based on industry-recognized standards, including the OWASP Top 10 for LLM Applications and the Penetration Testing Execution Standard (PTES).

**Conclusion**
<br>
Based on the testing performed, {{ firm.firm_name }} confirms that {{ client.name }} has subjected the {{ project.application_name }} AI implementation to a rigorous security assessment. The organization has demonstrated a strong commitment to security by engaging in proactive testing and maintaining robust foundational controls.

{% elif project.project_type == 'Cloud Penetration Test' %}
The assessment followed a comprehensive methodology based on industry-recognized standards, including the CIS Foundations Benchmarks and cloud provider best practices.

**Conclusion**
<br>
Based on the testing performed, {{ firm.firm_name }} confirms that {{ client.name }} has subjected its cloud environment to a rigorous security assessment. The organization has demonstrated a strong commitment to security by engaging in proactive testing and maintaining robust foundational controls.

{% else %}
The assessment followed a comprehensive methodology based on industry-recognized standards, including the OWASP Web Security Testing Guide (WSTG) and the Penetration Testing Execution Standard (PTES), tailored specifically to the application.

**Conclusion**
<br>
Based on the testing performed, {{ firm.firm_name }} confirms that {{ client.name }} has subjected the {{ project.application_name }} application to a rigorous security assessment. The organization has demonstrated a strong commitment to security by engaging in proactive testing and maintaining robust foundational controls.
{% endif %}

This attestation represents a point-in-time assessment of the environment as it existed during the testing window.

Sincerely,

<div style="font-family: 'Alex Brush', cursive; font-size: 16pt; margin-top: 15px; margin-bottom: 5px; color: #333;">
{{ tester.name }}
</div>

**{{ tester.name }}**<br>
{{ tester.title }}<br>
{{ firm.firm_name }}
