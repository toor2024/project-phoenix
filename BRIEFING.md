

## Top 3 Risks

1. **OpenSSH User Enumeration** — 192.168.56.101 (Metasploitable2)  
   - Risk Score: 20 (Impact 4, Likelihood 5)  
   - Owner: Blue Team  
   - Note: Remote user enumeration possible via SSH banner behavior.

2. **FTP Server Allows Anonymous Login** — 192.168.56.101 (Metasploitable2)  
   - Risk Score: 16 (Impact 4, Likelihood 4)  
   - Owner: Blue Team  
   - Note: Anonymous FTP login detected on target.

## Mitigations

## Appendix (Mapping Rules)

- **Impact (1–5)** = `assetCriticality` from `assets.csv`
- **Likelihood (1–5)** derived from `cvss`
- **Risk Score** = `impact × likelihood`
- **Sorting**: descending by `riskScore`
- **Asset join**: findings included only if `host` IP appears in `assets.csv`
