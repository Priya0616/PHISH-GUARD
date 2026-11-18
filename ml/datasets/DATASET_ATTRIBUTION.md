# PhishGuard ML Dataset Documentation & Attribution

## 1. Purpose & Licensing
The datasets in `ml/datasets/` provide an open, reproducible benchmark corpus for training and evaluating PhishGuard's URL and Email phishing classification models without redistributing third-party proprietary or PII-laden email archives.

- **License**: MIT License (original curated benchmark corpus for defensive security research and education).
- **Attribution & Lineage**:
  - Benign URL structural distributions follow top-tier Tranco / Cloudflare Radar domain patterns (root domains, standard HTTPS, documentation paths, OAuth callbacks, CDN assets).
  - Phishing URL patterns are modeled on publicly documented phishing taxonomies from **PhishTank**, **OpenPhish**, **URLhaus**, and **APWG Phishing Activity Trends Reports** (credential harvesting paths, brand typosquatting, Punycode IDN homographs, IP-literal hosts, open-redirect query parameters, URL shorteners, and suspicious TLDs).
  - Email phishing samples are synthetic, sanitized representations modeled on documented social engineering lures from the **Nazario Phishing Corpus** and **MITRE ATT&CK T1566 (Phishing)** categories (credential harvesting, invoice/wire fraud, MFA fatigue, IT helpdesk impersonation, and benign transactional/workplace correspondence).

## 2. Dataset Specifications
1. `phishing_urls_corpus.csv`: 240 labeled URLs (120 benign `0`, 120 phishing `1`).
2. `phishing_emails_corpus.csv`: 120 labeled email samples (60 benign `0`, 60 phishing `1`) with `subject`, `body`, and `label`.

## 3. Data Leakage Prevention & Limitations
- Stratified 80/20 train/test split is performed before any Z-score scaling or TF-IDF vocabulary/IDF calculation.
- **Model Confidence Limitations**: Classifier probability estimates reflect statistical similarity to lexical and structural patterns in this corpus. They are NOT calibrated guarantees of safety or malice; novel zero-day phishing on compromised legitimate infrastructure may receive low lexical risk scores, and complex enterprise SaaS SSO URLs may exhibit high lexical entropy.
