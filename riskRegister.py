import argparse
import csv
import xml.etree.ElementTree as ET

def cvssToLikelihood(cvss):
    try:
        c = float(cvss)
    except Exception:
        return 2
    if c >= 9.0: return 5
    if c >= 7.0: return 4
    if c >= 4.0: return 3
    if c > 0.0: return 2
    return 1

def loadAssets(path="assets.csv"):
    rows = []
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return rows

def getAssetField(assetRow, *keys):
    for k in keys:
        if k in assetRow and assetRow[k] != "":
            return assetRow[k]
    return ""

def parseGvmXml(xmlPath):
    findings = []
    tree = ET.parse(xmlPath)
    root = tree.getroot()
    for result in root.iterfind('.//result'):
        findings.append({
            'host': (result.findtext('host') or '').strip(),
            'name': (result.findtext('name') or '').strip(),
            'description': (result.findtext('description') or '').strip(),
            'cvss': (result.findtext('severity') or '').strip(),
        })
    return findings

def buildRiskRows(findings, assetsRows):
    impactByIp = {}
    assetNameByIp = {}
    ownerByIp = {}
    for r in assetsRows:
        ip = getAssetField(r, 'ipAddress', 'ip_address')
        if not ip:
            continue
        criticalityRaw = getAssetField(r, 'assetCriticality', 'asset_criticality') or "1"
        try:
            impactVal = int(criticalityRaw)
        except Exception:
            impactVal = 1
        impactByIp[ip] = impactVal
        assetNameByIp[ip] = getAssetField(r, 'assetName', 'asset_name')
        ownerByIp[ip] = getAssetField(r, 'assetOwner', 'asset_owner')

    out = []
    for f in findings:
        ip = f.get('host', '')
        if ip not in impactByIp:
            continue
        impact = impactByIp[ip]
        likelihood = cvssToLikelihood(f.get('cvss', ''))
        riskScore = impact * likelihood
        out.append({
            'ipAddress': ip,
            'assetName': assetNameByIp.get(ip, ''),
            'assetOwner': ownerByIp.get(ip, ''),
            'vulnerability': f.get('name', ''),
            'cvss': f.get('cvss', ''),
            'impact': impact,
            'likelihood': likelihood,
            'riskScore': riskScore,
            'description': f.get('description', ''),
        })
    out.sort(key=lambda r: r['riskScore'], reverse=True)
    return out

def writeCsv(rows, path="riskRegister.csv"):
    fields = [
        'ipAddress','assetName','assetOwner',
        'vulnerability','cvss','impact','likelihood','riskScore','description'
    ]
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

def main():
    ap = argparse.ArgumentParser(description="Project Phoenix risk register (camelCase)")
    ap.add_argument("--assets", "--assetsPath", dest="assetsPath", default="assets.csv")
    ap.add_argument("--report-xml", "--reportXml", dest="reportXml", default="report_sample.xml")
    ap.add_argument("--out", "--outPath", dest="outPath", default="riskRegister.csv")
    args = ap.parse_args()

    assets = loadAssets(args.assetsPath)
    print(f"Loaded {len(assets)} asset(s).")

    findings = parseGvmXml(args.reportXml)
    print(f"Parsed {len(findings)} finding(s).")
    if findings:
        f0 = findings[0]
        likelihood = cvssToLikelihood(f0.get('cvss', ''))
        demoImpact = 4
        demoRisk = demoImpact * likelihood
        print(f"Example: {f0['host']} — {f0['name']} (CVSS {f0['cvss']})")
        print(f"Test risk: impact {demoImpact} × likelihood {likelihood} = {demoRisk}")

    rowsOut = buildRiskRows(findings, assets)
    writeCsv(rowsOut, args.outPath)
    print(f"Wrote {args.outPath} with {len(rowsOut)} row(s).")

if __name__ == "__main__":
    main()
