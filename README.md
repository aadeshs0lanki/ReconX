# ReconX 🚀  
**Automated Web Application Reconnaissance Framework**

ReconX is a **production-grade web reconnaissance automation tool** designed for **Web Application Penetration Testing (WAPT)**, **bug bounty hunting**, and **red team reconnaissance**.

It orchestrates industry-standard open-source tools into a **fast, parallel, and reliable recon pipeline**, producing clean **TXT and HTML reports** with full attack-surface visibility.

---

## ✨ Features

- 🔍 End-to-end WAPT recon pipeline
- ⚡ Parallel execution (3–5× faster)
- 📊 Live progress bars with percentage, ETA & elapsed time
- 🧠 Automatic tool & dependency installation
- 🧱 OS-aware (Kali / Ubuntu friendly)
- 📁 Clean, structured output artifacts
- 📄 Human-readable TXT & HTML reports
- ♻️ Safe to re-run (idempotent design)

---

## 🧠 Recon Pipeline

```text
Scope Input (scope.txt)
        ↓
Subdomain Discovery
(subfinder, assetfinder, amass)
        ↓
DNS Resolution
(dnsx)
        ↓
HTTP Probing
(httpx)
        ↓
Port Scanning
(naabu)
        ↓
Technology Fingerprinting
(whatweb)
        ↓
URL Discovery
(gau, waybackurls, katana)
        ↓
JavaScript Recon
(subjs)
        ↓
Parameter Mining
(ParamSpider, Arjun)
        ↓
Vulnerability Scanning
(nuclei)
        ↓
Reports (TXT / HTML)
