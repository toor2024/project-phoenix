#!/usr/bin/env python3
import csv
import xml.etree.ElementTree as ET

def parse_gvm_xml(xml_path):
    findings = []
    tree = ET.parse(xml_path)
    root = tree.getroot()
    for result in root.iterfind('.//result'):
        findings.append({
            'host': (result.findtext('host') or '').strip(),
            'name': (result.findtext('name') or '').strip(),
            'description': (result.findtext('description') or '').strip(),
            'cvss': (result.findtext('severity') or '').strip(),
        })
    return findings

def cvss_to_likelihood(cvss):
    try:
        c = float(cvss)
    except Exception:
        return 2  # default if missing
    if c >= 9.0:
        return 5
    if c >= 7.0:
        return 4
    if c >= 4.0:
        return 3
    if c > 0.0:
        return 2
    return 1

def load_assets(path="assets.csv"):
    assets = []
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            assets.append(row)
    return assets

def build_risk_rows(findings, assets_rows):
    # make impact lookup by IP from assets.csv
    impact_by_ip = {r['ip_address']: int(r.get('asset_criticality', '1') or 1) for r in assets_rows}
    out = []
    for f in findings:
        ip = f['host']
        if ip not in impact_by_ip:
            continue  # skip hosts not in assets.csv
        impact = impact_by_ip[ip]
        likelihood = cvss_to_likelihood(f['cvss'])
        risk_score = impact * likelihood
        out.append({
            'ip_address': ip,
            'vulnerability': f['name'],
            'cvss': f['cvss'],
            'impact': impact,
            'likelihood': likelihood,
            'risk_score': risk_score,
            'description': f['description'],
        })
    # highest risk first
    out.sort(key=lambda r: r['risk_score'], reverse=True)
    return out

def write_csv(rows, path="risk_register.csv"):
    fields = ['ip_address','vulnerability','cvss','impact','likelihood','risk_score','description']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

if __name__ == "__main__":
    rows = load_assets()
    print(f"Loaded {len(rows)} asset(s).")

    findings = parse_gvm_xml("report_sample.xml")
    print(f"Parsed {len(findings)} finding(s).")
    if findings:
        f = findings[0]
        print(f"Example: {f['host']} — {f['name']} (CVSS {f['cvss']})")

        # quick test risk calc for the example
        impact = 4  # placeholder from assets.csv for this IP
        likelihood = cvss_to_likelihood(f['cvss'])
        risk_score = impact * likelihood
        print(f"Test risk: impact {impact} × likelihood {likelihood} = {risk_score}")

    # write full CSV
    rows_out = build_risk_rows(findings, rows)
    write_csv(rows_out, "risk_register.csv")
    print(f"Wrote risk_register.csv with {len(rows_out)} row(s).")
