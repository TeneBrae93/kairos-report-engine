

<div class="cover-page" style="page-break-after: always; height: 950px; position: relative; font-family: sans-serif; padding-top: 150px; padding-left: 50px; box-sizing: border-box;">

<div style="font-size: 42pt; text-transform: uppercase; line-height: 1.1; font-weight: 900; margin-bottom: 10px; color: #000;">
{{ project.project_type | replace(' ', '<br>') | safe }}
</div>

<div style="font-size: 28pt; text-transform: uppercase; font-weight: 900; margin-bottom: 60px; color: #000;">
{{ project.application_name }}
</div>

<div style="font-size: 22pt; text-transform: uppercase; font-weight: 900; margin-bottom: 20px; color: #000;">
{{ client.name }}
</div>

<div style="font-size: 22pt; font-weight: 900; color: #000;">
{{ project.report_date_formatted }}
</div>

<div style="position: absolute; bottom: 50px; left: 50px; font-size: 12pt; line-height: 1.4; color: #333;">
{{ firm.firm_name }}<br>
{{ firm.firm_website }}
</div>

</div>

<div style="page-break-after: always;" markdown="1">
<div style="font-size: 24pt; font-weight: bold; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; color: #1a202c; margin-top: 1em; margin-bottom: 1em;">
    Table of Contents
</div>
[TOC]
</div>

# Executive Summary

## Introduction
The Assessment Team at {{ firm.firm_name }} is pleased to present the results of the {{ project.project_type }}
for {{ client.name }}. This assessment was performed by {{ tester.name }}.
{{ tester.name }} is {{ tester.description }}

## Methodology and Approach
{% if project.project_type == 'Web Application Penetration Test' or not project.project_type %}
A full penetration test was conducted on the target web application and associated endpoints
between {{ project.start_date_formatted }} and {{ project.end_date_formatted }}. The objective of this engagement was to emulate a malicious
actor (ranging from an unauthenticated external attacker to a compromised user) to identify and
exploit vulnerabilities that could impact the confidentiality, integrity, and availability of the
application, its underlying data, and the hosting infrastructure.

The assessment followed a comprehensive methodology based on industry-recognized
standards, including the OWASP Web Security Testing Guide (WSTG) and the Penetration
Testing Execution Standard (PTES). Key phases of the engagement included:

**1. Reconnaissance & Discovery:** Mapping the application structure, enumerating
subdomains and API endpoints, analyzing the technology stack, and identifying potential
entry points (user inputs, file uploads, and parameters).

**2. Vulnerability Analysis:** Systematically identifying security flaws such as injection
vulnerabilities, broken authentication, sensitive data exposure, and logic flaws across the
in-scope assets. This phase relies heavily on the OWASP Top 10 framework.

**3. Exploitation:** Safely and non-disruptively attempting to execute identified vulnerabilities
to bypass security controls, escalate privileges (vertical or horizontal), and manipulate
business logic.

**4. Post-Exploitation:** Demonstrating the potential business impact of a successful breach,
including unauthorized data access, database compromise, or the ability to pivot from
the web application to the underlying server environment.

Testing was performed under the strict Rules of Engagement provided by {{ client.name }} to ensure
the stability of the production environment. This report details the high-level findings and
provides strategic recommendations to address the identified risks.

{% elif project.project_type == 'Internal Network Penetration Test' %}
A full penetration test was conducted on the internal network infrastructure
between {{ project.start_date_formatted }} and {{ project.end_date_formatted }}. The objective of this engagement was to emulate an internal malicious actor (e.g., a rogue employee or an attacker who has breached the perimeter) to identify and exploit vulnerabilities that could impact the confidentiality, integrity, and availability of internal systems.

The assessment followed a comprehensive methodology based on industry-recognized standards, including the Penetration Testing Execution Standard (PTES). Key phases of the engagement included:

**1. Reconnaissance & Discovery:** Active and passive host discovery, port scanning, and service enumeration to map the internal network topology and identify live assets.

**2. Vulnerability Analysis:** Systematically identifying security flaws such as missing patches, misconfigurations, weak credentials, and legacy protocols across the in-scope assets.

**3. Exploitation:** Safely and non-disruptively attempting to execute identified vulnerabilities to bypass security controls, escalate privileges, and compromise domain controllers or critical servers.

**4. Post-Exploitation:** Demonstrating the potential business impact of a successful breach, including unauthorized data access, lateral movement, and persistence within the internal environment.

Testing was performed under the strict Rules of Engagement provided by {{ client.name }} to ensure the stability of the production environment. This report details the high-level findings and provides strategic recommendations to address the identified risks.

{% elif project.project_type == 'External Network Penetration Test' %}
A full penetration test was conducted on the external-facing network infrastructure
between {{ project.start_date_formatted }} and {{ project.end_date_formatted }}. The objective of this engagement was to emulate an external malicious actor to identify and exploit vulnerabilities that could impact the confidentiality, integrity, and availability of the organization's public-facing systems.

The assessment followed a comprehensive methodology based on industry-recognized standards, including the Penetration Testing Execution Standard (PTES). Key phases of the engagement included:

**1. Reconnaissance & Discovery:** Open-source intelligence gathering (OSINT), DNS enumeration, port scanning, and service identification to map the external attack surface.

**2. Vulnerability Analysis:** Systematically identifying security flaws such as exposed administrative interfaces, vulnerable services, missing patches, and misconfigurations across the in-scope assets.

**3. Exploitation:** Safely and non-disruptively attempting to execute identified vulnerabilities to bypass perimeter security controls and gain unauthorized access to internal systems or sensitive data.

**4. Post-Exploitation:** Demonstrating the potential business impact of a successful breach, including unauthorized data access or the ability to pivot into the internal network environment.

Testing was performed under the strict Rules of Engagement provided by {{ client.name }} to ensure the stability of the production environment. This report details the high-level findings and provides strategic recommendations to address the identified risks.

{% elif project.project_type == 'AI/LLM Penetration Test' %}
A targeted penetration test was conducted on the artificial intelligence and large language model (LLM) implementation
between {{ project.start_date_formatted }} and {{ project.end_date_formatted }}. The objective of this engagement was to evaluate the security, safety, and robustness of the AI model and its integration against adversarial attacks.

The assessment followed a comprehensive methodology based on industry-recognized standards, including the OWASP Top 10 for LLM Applications. Key phases of the engagement included:

**1. Reconnaissance & Discovery:** Mapping the AI application architecture, identifying model inputs, outputs, system prompts, and integrations with external APIs or databases.

**2. Vulnerability Analysis:** Systematically identifying security flaws such as prompt injection vulnerabilities, training data poisoning risks, model denial of service, and insecure output handling.

**3. Exploitation:** Safely and non-disruptively attempting to execute identified vulnerabilities, including jailbreaks to bypass safety filters, prompt injections to manipulate model behavior, and extraction of sensitive data or underlying prompts.

**4. Post-Exploitation:** Demonstrating the potential business impact of a successful attack, including unauthorized access to backend systems via model integrations, data exfiltration, or generation of harmful content.

Testing was performed under the strict Rules of Engagement provided by {{ client.name }} to ensure the stability of the production environment. This report details the high-level findings and provides strategic recommendations to address the identified risks.

{% elif project.project_type == 'Cloud Penetration Test' %}
A comprehensive penetration test and security review was conducted on the cloud environment
between {{ project.start_date_formatted }} and {{ project.end_date_formatted }}. The objective of this engagement was to emulate a malicious actor to identify and exploit vulnerabilities, misconfigurations, and weak access controls that could impact the confidentiality, integrity, and availability of the cloud infrastructure and hosted services.

The assessment followed a comprehensive methodology based on industry-recognized standards, including the CIS Foundations Benchmarks and cloud provider best practices. Key phases of the engagement included:

**1. Reconnaissance & Discovery:** Enumerating cloud assets, analyzing Identity and Access Management (IAM) configurations, and reviewing network security groups and routing tables.

**2. Vulnerability Analysis:** Systematically identifying security flaws such as publicly exposed storage buckets, overly permissive IAM roles, unencrypted data stores, and vulnerable compute instances.

**3. Exploitation:** Safely and non-disruptively attempting to execute identified vulnerabilities to bypass security controls, escalate privileges within the cloud environment, and access sensitive resources.

**4. Post-Exploitation:** Demonstrating the potential business impact of a successful breach, including unauthorized data access, lateral movement between cloud services, and potential compromise of the control plane.

Testing was performed under the strict Rules of Engagement provided by {{ client.name }} to ensure the stability of the production environment. This report details the high-level findings and provides strategic recommendations to address the identified risks.
{% endif %}

<div style="page-break-inside: avoid;" markdown="1">

## Scope 
The list of hosts covered by this assessment included: 

{{ project.hosts }}

</div>

## Summary of Strengths
Despite the identified vulnerabilities, the assessment noted several areas where {{ client.name }}
demonstrated a strong and mature security posture.

{{ firm.summary_of_strengths }}

## Summary of Weaknesses

The assessment identified several security weaknesses that increase the organization's overall
risk exposure. The top security themes, which allowed for the most severe compromises, are
summarized below:

{{ firm.summary_of_weaknesses }}

## Summary of Findings
A total of {{ findings|length }} issues were identified during this assessment. Risk ratings were assigned based on their Common Vulnerability Scoring System (CVSS) base score using the following mapping. 

<div style="page-break-inside: avoid;">
<table style="width: 60%; margin: 20px auto; border-collapse: collapse; text-align: left; border: 1px solid #333;">
  <thead>
    <tr>
      <th style="border: 1px solid #333; background-color: #555; color: white; padding: 8px; font-weight: bold;">CVSSv4 Score</th>
      <th style="border: 1px solid #333; background-color: #555; color: white; padding: 8px; font-weight: bold;">Risk Rating</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="border: 1px solid #333; padding: 8px;">9.0 to 10.0</td>
      <td style="border: 1px solid #333; padding: 8px; background-color: #9b2c2c; color: white; font-weight: bold; text-align: center;">Critical</td>
    </tr>
    <tr>
      <td style="border: 1px solid #333; padding: 8px;">7.0 to 8.9</td>
      <td style="border: 1px solid #333; padding: 8px; background-color: #c53030; color: white; font-weight: bold; text-align: center;">High</td>
    </tr>
    <tr>
      <td style="border: 1px solid #333; padding: 8px;">4.0 to 6.9</td>
      <td style="border: 1px solid #333; padding: 8px; background-color: #dd6b20; color: white; font-weight: bold; text-align: center;">Medium</td>
    </tr>
    <tr>
      <td style="border: 1px solid #333; padding: 8px;">0.1 to 3.9</td>
      <td style="border: 1px solid #333; padding: 8px; background-color: #38a169; color: white; font-weight: bold; text-align: center;">Low</td>
    </tr>
    <tr>
      <td style="border: 1px solid #333; padding: 8px;">n/a</td>
      <td style="border: 1px solid #333; padding: 8px; background-color: #3182ce; color: white; font-weight: bold; text-align: center;">Informational</td>
    </tr>
  </tbody>
</table>
</div>

**Critical**<br>
Direct, immediate, and comprehensive compromise. Exploitation could lead to complete system
takeover, major data breaches (e.g., all customer data), or total loss of business
function/availability with minimal effort.

**High**<br>
Significant compromise. Exploitation could result in unauthorized access to sensitive data (e.g.,
individual user accounts, proprietary information) or major disruption to key business services.
Exploitation often requires some level of effort.

**Medium**<br>
Moderate impact. Exploitation could allow limited access to non-critical data or system
functionality, or could be used to facilitate a more significant attack when combined with other
weaknesses. It requires more effort or specific conditions to exploit.

**Low**<br>
Minor impact. The vulnerability is typically difficult to exploit, would only result in very limited
non-sensitive information disclosure, or is restricted to isolated areas. The primary risk is often
providing a hint to an attacker for future, more serious attacks.

**Informational**<br>
No direct security risk. These are general observations, best practices not followed, or
configuration details that don't pose a vulnerability on their own but are noted for completeness.

{{ findings.table }}

{{ project.findings_chart }}

<div style="page-break-before: always;"></div>

# Detailed Findings

{{ findings.detailed_findings }}

<div style="page-break-before: always;"></div>

# Appendices

## Appendix A: Tools Used
{{ project.tools_used_table }}