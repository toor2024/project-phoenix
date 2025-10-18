# Project Phoenix – Briefing Report

## Scope & Setup

## Method

## Top 3 Risks

## Mitigations

## Appendix (Mapping Rules)

- **Impact (1–5)** = `asset_criticality` from `assets.csv`  
  - 1 = Low, 3 = Moderate, 5 = Critical business impact
- **Likelihood (1–5)** derived from report severity (CVSS-like):
  - 9.0–10.0 → 5  
  - 7.0–8.9 → 4  
  - 4.0–6.9 → 3  
  - 0.1–3.9 → 2  
  - 0.0 or missing → 1
- **Risk Score** = `Impact × Likelihood`
- **Sorting**: descending by Risk Score (highest risk first)
- **Asset join**: findings are included only if `host` IP appears in `assets.csv`.
