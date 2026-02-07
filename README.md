# MinIO Security Assessment Tool

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](#)
[![MinIO](https://img.shields.io/badge/Target-MinIO%20S3%20Compatible-orange.svg)](https://min.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A comprehensive **security assessment & exploitation helper** for MinIO instances.  
It automates discovery, authentication checks, S3 enumeration, privilege validation, exposed endpoint testing, CVE checks, and generates a consolidated report with actionable next steps.

██████╗ ██████╗ ██╗   ██╗███╗   ██╗ ██████╗ ███╗   ███╗██╗
██╔══██╗╚════██╗██║   ██║████╗  ██║██╔═══██╗████╗ ████║██║
██║  ██║ █████╔╝██║   ██║██╔██╗ ██║██║   ██║██╔████╔██║██║
██║  ██║ ╚═══██╗╚██╗ ██╔╝██║╚██╗██║██║   ██║██║╚██╔╝██║██║
██████╔╝██████╔╝ ╚████╔╝ ██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║
╚═════╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝
d3vn0mi

---

## 📋 Table of Contents

- [Overview](#-overview)
- [What It Tests](#-what-it-tests)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Examples](#-examples)
- [Sample Output](#-sample-output)
- [Known CVEs Covered](#-known-cves-covered)
- [Mitigation](#-mitigation)
- [Disclaimer](#-disclaimer)
- [References](#-references)
- [Author](#-author)
- [License](#-license)
- [Contributing](#-contributing)
- [⭐ Show Your Support](#-show-your-support)

---

## 🔍 Overview

MinIO is widely deployed as an S3-compatible object storage solution, often exposed internally (or accidentally externally).  
This tool helps assess a target MinIO instance using provided credentials and common exposure patterns, then surfaces **practical exploitation routes** (when applicable), such as:

- exposed console or console API
- S3 bucket access with weak/over-privileged keys
- admin-level access via `mc`
- exposed metrics/debug endpoints
- path traversal checks (console API)
- webhook configuration abuse (SSRF/callback paths)

> ⚠️ **Authorized testing only.** See [Disclaimer](#-disclaimer).

---

## 🧪 What It Tests

The script runs these checks (in order):

1. **MinIO Console Access**
   - Tries common ports (target port + 9000/9001) and detects MinIO console pages

2. **Console API Authentication**
   - Tests `/api/v1/login` endpoints and attempts to obtain token/session

3. **S3 API Access**
   - Uses `boto3` to list buckets and enumerate objects in a target bucket

4. **MinIO Client (`mc`) Availability**
   - Detects if `mc` is installed and attempts alias configuration

5. **Admin Privilege Confirmation**
   - Runs `mc admin info` and user listing when possible

6. **Exposed Endpoints**
   - Checks common metrics/health/debug endpoints for exposure

7. **Version Detection**
   - Attempts version extraction via `Server` header (when available)

8. **Path Traversal Test**
   - Probes common traversal payloads (focused on console API patterns)

9. **Webhook Capability**
   - If admin, checks ability to read webhook notify config and prints an abuse workflow

---

## ✨ Features

- ✅ **Console discovery** across common ports
- ✅ **Console API login test** (token/session acquisition)
- ✅ **S3 enumeration** (bucket listing + object preview)
- ✅ **`mc` integration** for operational and admin checks
- ✅ **Admin privilege detection**
- ✅ **Exposure scanning** for metrics/health/debug endpoints
- ✅ **Path traversal probing** (console API patterns)
- ✅ **Webhook config capability detection** (SSRF/callback path)
- ✅ **Color-coded output** + **final assessment report**
- ✅ **Verbose mode** for troubleshooting

---

## 📦 Installation

### Requirements

- Python **3.8+**
- `pip`
- Dependencies:
  - `requests`
  - `boto3`

### Install dependencies

```bash
pip install requests boto3

(Optional) Install MinIO Client (mc)

wget https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc
sudo mv mc /usr/local/bin/
mc --version
```

⸻

🚀 Usage

Basic Syntax

python3 minio_scanner.py -t <target> -p <port> -a <access_key> -s <secret_key> [options]

Command-Line Options

required arguments:
  -t, --target         Target hostname or IP
  -a, --access-key     AWS/MinIO access key
  -s, --secret-key     AWS/MinIO secret key

optional arguments:
  -p, --port           MinIO port (default: 54321)
  -b, --bucket         Target bucket name (default: randomfacts)
  -v, --verbose        Verbose output


⸻

📚 Examples

Standard run

python3 minio_scanner.py -t facts.htb -p 54321 -a AKIAxxxxxxxx -s SECRET_KEY

Verbose + custom bucket

python3 minio_scanner.py -t 10.10.11.50 -p 9000 -a ACCESS_KEY -s SECRET_KEY -b mybucket -v


⸻

📊 Sample Output

============================================================
   MinIO Security Assessment & Exploitation Tool
   Author: d3vn0mi | GitHub: github.com/d3vhthnnni
============================================================

[*] Target: 10.10.11.50:9000
[*] Access Key: AKIAxxxxxxxx
[*] Bucket: randomfacts

[+] MinIO Console FOUND at http://10.10.11.50:9001
[+] API Authentication SUCCESSFUL!
[+] S3 API Access SUCCESSFUL!
[+] Found 3 bucket(s):
    → randomfacts
    → backups
    → logs

[+] mc client is installed
[+] mc can access MinIO instance
[+] ADMIN PRIVILEGES CONFIRMED!

[+] Found 4 exposed endpoints
[✓] Path traversal: Not vulnerable

==================== ASSESSMENT REPORT ====================
[CRITICAL] Admin Privileges Confirmed
[HIGH]     S3 API Access Confirmed
[MEDIUM]   Exposed Endpoints: /minio/metrics, /minio/health/live, ...
============================================================


⸻

🐛 Known CVEs Covered

This tool prints and/or probes for notable MinIO issues to guide verification:

CVE	Type	Notes
CVE-2024-24747	Path Traversal	Console API path traversal patterns
CVE-2023-28432	Info Disclosure / Priv Esc	Known MinIO cluster-related exposure history
CVE-2023-28434	Admin Priv Esc	Cluster admin escalation history
CVE-2021-21287	Auth Bypass	Historical authentication bypass

Important: Version-based vulnerability determination can require manual confirmation depending on deployment and component versions (server vs console).

⸻

🛡️ Mitigation

Immediate Actions
	1.	Restrict access to MinIO console (9001) and API endpoints
	2.	Rotate credentials and apply least privilege (avoid admin keys for apps)
	3.	Patch/upgrade MinIO + console to a current, supported release
	4.	Disable or lock down:
	•	debug endpoints (/minio/debug/pprof/)
	•	public metrics endpoints
	•	webhook configuration (or restrict outbound egress)

Long-Term Hardening
	•	Put MinIO behind VPN / internal network segmentation
	•	Enforce MFA / SSO where supported
	•	Use dedicated service accounts per application
	•	Monitor logs for suspicious access (bucket enumeration, config changes, user listing)

⸻

⚠️ Disclaimer

This tool is provided for educational and authorized security testing purposes only.

Legal Notice:
	•	Only run this against systems you own or have explicit written permission to test
	•	Unauthorized access is illegal and may violate local laws and regulations
	•	The author assumes no liability for misuse or damage caused by this tool
	•	You are solely responsible for your actions

Ethical Use:
	•	Obtain authorization before testing
	•	Respect scope limitations
	•	Follow responsible disclosure practices

⸻

📖 References
	•	MinIO Documentation: https://min.io/docs/
	•	MinIO Client (mc) Docs: https://min.io/docs/minio/linux/reference/minio-mc.html
	•	NVD (CVE search): https://nvd.nist.gov/

If you want, I can also add direct links to each CVE advisory you’re targeting in your known_cves list.

⸻

👤 Author

d3vn0mi
	•	GitHub: https://github.com/d3vn0mi

⸻

📝 License

This project is licensed under the MIT License — see the LICENSE￼ file for details.

⸻

🤝 Contributing

Contributions, issues, and feature requests are welcome.
	•	Open an issue with repro steps / expected behavior
	•	Submit a PR with clear description and test notes

⸻

⭐ Show Your Support

If this project helped you, consider giving it a ⭐ on GitHub!

If you tell me the **repo name** (and whether you want **MIT** or a different license), I can also generate:
- a matching `requirements.txt`
- a `LICENSE` file
- and a cleaner “References” section with the exact advisories for the CVEs you listed.
