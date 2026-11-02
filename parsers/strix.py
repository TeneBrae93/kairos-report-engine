import json
import logging
import re
import markdown
from utils.helpers import sanitize_rich_html

logger = logging.getLogger(__name__)

# Official FIRST CVSS v4.0 MacroVector Base Lookup Table
# Keys are (EQ1, EQ2, EQ3, EQ4, EQ5, EQ6) for base metrics (where EQ5='0' and EQ6='0' for EQ3 in {0,1}, EQ6='1' for EQ3='2')
_CVSS4_BASE_LOOKUP: dict[str, float] = {
    "000000": 10.0,
    "000100": 9.3,
    "000200": 8.7,
    "001000": 9.2,
    "001100": 8.6,
    "001200": 7.1,
    "002001": 8.2,
    "002101": 6.9,
    "002201": 6.9,
    "010000": 9.5,
    "010100": 8.4,
    "010200": 7.7,
    "011000": 8.7,
    "011100": 7.5,
    "011200": 5.8,
    "012001": 7.2,
    "012101": 5.8,
    "012201": 6.3,
    "100000": 9.4,
    "100100": 8.6,
    "100200": 7.5,
    "101000": 8.5,
    "101100": 7.4,
    "101200": 5.5,
    "102001": 7.0,
    "102101": 5.4,
    "102201": 5.3,
    "110000": 8.6,
    "110100": 7.6,
    "110200": 6.2,
    "111000": 7.6,
    "111100": 6.0,
    "111200": 4.8,
    "112001": 5.9,
    "112101": 4.9,
    "112201": 4.8,
    "200000": 8.3,
    "200100": 7.2,
    "200200": 5.3,
    "201000": 7.0,
    "201100": 5.7,
    "201200": 4.0,
    "202001": 5.4,
    "202101": 4.1,
    "202201": 4.0,
    "210000": 7.3,
    "210100": 6.0,
    "210200": 4.7,
    "211000": 6.1,
    "211100": 4.8,
    "211200": 2.3,
    "212001": 4.6,
    "212101": 3.5,
    "212201": 2.1,
}


def convert_to_cvss4(
    cvss_breakdown: dict | None,
    fallback_score: float = 0.0,
    existing_vector: str = "",
) -> tuple[float, str]:
    """
    Convert a Strix cvss_breakdown dictionary (CVSS v3.x metrics) into a
    CVSS v4.0 vector string and calculate the corresponding CVSS v4.0 base score.
    """
    if existing_vector and existing_vector.strip().upper().startswith("CVSS:4.0/"):
        vec = existing_vector.strip()
        score = calculate_cvss4_score_from_vector(vec, fallback_score=fallback_score)
        return score, vec

    if not isinstance(cvss_breakdown, dict) or not cvss_breakdown:
        return round(float(fallback_score or 0.0), 1), ""

    av_raw = str(cvss_breakdown.get("attack_vector", "N")).strip().upper()
    av = av_raw if av_raw in ("N", "A", "L", "P") else "N"

    ac_raw = str(cvss_breakdown.get("attack_complexity", "L")).strip().upper()
    ac = ac_raw if ac_raw in ("L", "H") else "L"

    at_raw = str(cvss_breakdown.get("attack_requirements", "N")).strip().upper()
    at = at_raw if at_raw in ("N", "P") else "N"

    pr_raw = str(cvss_breakdown.get("privileges_required", "N")).strip().upper()
    pr = pr_raw if pr_raw in ("N", "L", "H") else "N"

    ui_raw = str(cvss_breakdown.get("user_interaction", "N")).strip().upper()
    if ui_raw == "R":
        ui = "A"  # CVSS v3 Required -> CVSS v4 Active
    elif ui_raw in ("N", "P", "A"):
        ui = ui_raw
    else:
        ui = "N"

    vc_raw = str(cvss_breakdown.get("confidentiality", "N")).strip().upper()
    vc = vc_raw if vc_raw in ("N", "L", "H") else "N"

    vi_raw = str(cvss_breakdown.get("integrity", "N")).strip().upper()
    vi = vi_raw if vi_raw in ("N", "L", "H") else "N"

    va_raw = str(cvss_breakdown.get("availability", "N")).strip().upper()
    va = va_raw if va_raw in ("N", "L", "H") else "N"

    scope_raw = str(cvss_breakdown.get("scope", "U")).strip().upper()
    if scope_raw == "C":
        sc, si, sa = vc, vi, va
    else:
        sc = str(cvss_breakdown.get("subsequent_confidentiality", "N")).strip().upper()
        si = str(cvss_breakdown.get("subsequent_integrity", "N")).strip().upper()
        sa = str(cvss_breakdown.get("subsequent_availability", "N")).strip().upper()
        sc = sc if sc in ("N", "L", "H") else "N"
        si = si if si in ("N", "L", "H") else "N"
        sa = sa if sa in ("N", "L", "H") else "N"

    vector = (
        f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}"
        f"/VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}"
    )
    score = calculate_cvss4_score_from_vector(vector, fallback_score=fallback_score)
    return score, vector


def calculate_cvss4_score_from_vector(vector: str, fallback_score: float = 0.0) -> float:
    """Calculate the CVSS v4.0 base score from a CVSS:4.0/... vector string."""
    try:
        metrics: dict[str, str] = {}
        for part in vector.split("/"):
            if ":" in part and not part.upper().startswith("CVSS"):
                k, v = part.split(":", 1)
                metrics[k.strip().upper()] = v.strip().upper()

        av = metrics.get("AV", "N")
        ac = metrics.get("AC", "L")
        at = metrics.get("AT", "N")
        pr = metrics.get("PR", "N")
        ui = metrics.get("UI", "N")
        vc = metrics.get("VC", "N")
        vi = metrics.get("VI", "N")
        va = metrics.get("VA", "N")
        sc = metrics.get("SC", "N")
        si = metrics.get("SI", "N")
        sa = metrics.get("SA", "N")

        if all(m == "N" for m in (vc, vi, va, sc, si, sa)):
            return 0.0

        # EQ1: 0 if AV:N and PR:N and UI:N; 1 if (AV:N or PR:N or UI:N) and not AV:P; else 2
        if av == "N" and pr == "N" and ui == "N":
            eq1 = "0"
        elif (av == "N" or pr == "N" or ui == "N") and av != "P":
            eq1 = "1"
        else:
            eq1 = "2"

        # EQ2: 0 if AC:L and AT:N; else 1
        eq2 = "0" if (ac == "L" and at == "N") else "1"

        # EQ3 & EQ6 (for Base metrics where CR=IR=AR=H)
        if vc == "H" and vi == "H":
            eq3, eq6 = "0", "0"
        elif vc == "H" or vi == "H" or va == "H":
            eq3, eq6 = "1", "0"
        else:
            eq3, eq6 = "2", "1"

        # EQ4 (for Base metrics where MSI=MSA=X)
        if sc == "H" or si == "H" or sa == "H":
            eq4 = "1"
        else:
            eq4 = "2"

        eq5 = "0"
        macro = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"
        base_val = _CVSS4_BASE_LOOKUP.get(macro)
        if base_val is None:
            return round(float(fallback_score or 0.0), 1)

        # Compute fine-grained severity distance within the MacroVector equivalence classes
        av_dist = {"N": 0, "A": 1, "L": 2, "P": 3}.get(av, 0)
        pr_dist = {"N": 0, "L": 1, "H": 2}.get(pr, 0)
        ui_dist = {"N": 0, "P": 1, "A": 2}.get(ui, 0)
        ac_dist = {"L": 0, "H": 1}.get(ac, 0)
        at_dist = {"N": 0, "P": 1}.get(at, 0)
        vc_dist = {"H": 0, "L": 1, "N": 2}.get(vc, 2)
        vi_dist = {"H": 0, "L": 1, "N": 2}.get(vi, 2)
        va_dist = {"H": 0, "L": 1, "N": 2}.get(va, 2)

        # Within-class step offsets (each step within an EQ reduces by ~0.1)
        eq1_offset = max(0, (av_dist + pr_dist + ui_dist) - (0 if eq1 == "0" else (1 if eq1 == "1" else 3)))
        eq2_offset = max(0, (ac_dist + at_dist) - (0 if eq2 == "0" else 1))
        if eq3 == "0":
            eq3_offset = va_dist
        elif eq3 == "1":
            eq3_offset = max(0, (vc_dist + vi_dist + va_dist) - 1)
        else:
            eq3_offset = max(0, (vc_dist + vi_dist + va_dist) - 3)

        adjustment = (eq1_offset + eq2_offset + eq3_offset) * 0.1
        final_score = max(0.1, min(10.0, round(base_val - adjustment, 1)))
        return final_score
    except Exception:
        return round(float(fallback_score or 0.0), 1)


def _format_strix_steps_to_reproduce(poc_description: str, poc_script_code: str) -> str:
    """Combine poc_description and poc_script_code into sanitized rich HTML for Steps to Reproduce."""
    parts: list[str] = []

    if poc_description and poc_description.strip():
        parts.append(poc_description.strip())

    if poc_script_code and poc_script_code.strip():
        code_str = poc_script_code.strip()
        if not code_str.startswith("```"):
            code_str = f"```\n{code_str}\n```"
        parts.append(code_str)

    if not parts:
        return ""

    combined_md = "\n\n".join(parts)
    html = markdown.markdown(combined_md, extensions=["fenced_code", "tables"])
    return sanitize_rich_html(html)


def parse_strix(file_path: str) -> list[dict]:
    """
    Parses a Strix vulnerabilities.json file and extracts vulnerability findings.

    Mapping:
      - title -> title
      - severity -> severity
      - target -> host
      - technical_analysis -> description (falls back to description)
      - poc_description + poc_script_code -> steps_to_reproduce
      - remediation_steps -> remediation
      - cvss / cvss_breakdown -> CVSSv4 score & CVSS:4.0 vector string
    """
    findings: list[dict] = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                items = data["vulnerabilities"]
            elif "findings" in data and isinstance(data["findings"], list):
                items = data["findings"]
            else:
                raise ValueError("Provided JSON object does not contain a 'vulnerabilities' or 'findings' list.")
        elif isinstance(data, list):
            items = data
        else:
            raise ValueError("Provided file is not a valid Strix JSON format (expected a list of findings).")

        severity_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
            "informational": "Info",
            "none": "Info",
        }

        for item in items:
            if not isinstance(item, dict):
                continue

            title = (item.get("title") or "Unknown Finding").strip()
            raw_sev = str(item.get("severity") or "info").strip().lower()
            severity = severity_map.get(raw_sev, "Info")

            host = str(item.get("target") or "").strip()
            path = str(item.get("endpoint") or "").strip()

            description = (item.get("technical_analysis") or item.get("description") or "").strip()
            remediation = (item.get("remediation_steps") or item.get("remediation") or "").strip()

            poc_desc = item.get("poc_description") or ""
            poc_code = item.get("poc_script_code") or ""
            steps_html = _format_strix_steps_to_reproduce(poc_desc, poc_code)

            try:
                raw_cvss = float(item.get("cvss") or 0.0)
            except (TypeError, ValueError):
                raw_cvss = 0.0

            cvss_score, cvss_vector = convert_to_cvss4(
                item.get("cvss_breakdown"),
                fallback_score=raw_cvss,
                existing_vector=str(item.get("cvss_vector") or ""),
            )

            # Populate references from explicit references or CWE ID if available
            refs_list: list[str] = []
            raw_refs = item.get("references") or item.get("refs")
            if isinstance(raw_refs, list):
                refs_list.extend(str(r).strip() for r in raw_refs if str(r).strip())
            elif isinstance(raw_refs, str) and raw_refs.strip():
                refs_list.append(raw_refs.strip())

            cwe = str(item.get("cwe") or "").strip()
            cwe_match = re.match(r"^CWE-(\d+)$", cwe, flags=re.IGNORECASE)
            if cwe_match:
                cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_match.group(1)}.html"
                if cwe_url not in refs_list:
                    refs_list.append(cwe_url)

            findings.append({
                "title": title,
                "severity": severity,
                "description": description,
                "remediation": remediation,
                "cvss": cvss_score,
                "cvss_vector": cvss_vector,
                "host": host,
                "path": path,
                "refs": "\n".join(refs_list),
                "steps_to_reproduce": steps_html,
            })

    except json.JSONDecodeError as e:
        logger.error(f"Error parsing Strix JSON file {file_path}: {e}")
        raise ValueError("Provided file is not a valid JSON file.")
    except Exception as e:
        logger.error(f"Unexpected error parsing Strix file {file_path}: {e}")
        raise

    return findings
