# MinIO Security Assessment Tool

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](#)
[![Target](https://img.shields.io/badge/Target-MinIO-orange.svg)](https://min.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A comprehensive **security assessment & exploitation helper** for MinIO instances.  
Automates discovery, authentication checks, S3 enumeration, privilege validation, exposed endpoint testing, CVE checks, and produces an actionable assessment report.

```
██████╗ ██████╗ ██╗   ██╗███╗   ██╗ ██████╗ ███╗   ███╗██╗
██╔══██╗╚════██╗██║   ██║████╗  ██║██╔═══██╗████╗ ████║██║
██║  ██║ █████╔╝██║   ██║██╔██╗ ██║██║   ██║██╔████╔██║██║
██║  ██║ ╚═══██╗╚██╗ ██╔╝██║╚██╗██║██║   ██║██║╚██╔╝██║██║
██████╔╝██████╔╝ ╚████╔╝ ██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║
╚═════╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝
                          d3vn0mi
```

---

## 📋 Table of Contents

- [MinIO Security Assessment Tool](#minio-security-assessment-tool)
  - [📋 Table of Contents](#-table-of-contents)
  - [🔍 Overview](#-overview)
  - [🧪 What It Tests](#-what-it-tests)
  - [✨ Features](#-features)
  - [📦 Installation](#-installation)
    - [Requirements](#requirements)
    - [Install dependencies](#install-dependencies)
    - [(Optional) Install MinIO Client (`mc`)](#optional-install-minio-client-mc)
  - [🚀 Usage](#-usage)
    - [Syntax](#syntax)
    - [Options](#options)
  - [📚 Examples](#-examples)
    - [Standard scan](#standard-scan)
    - [Verbose scan with custom bucket](#verbose-scan-with-custom-bucket)
  - [📊 Sample Output](#-sample-output)
  - [🐛 Known CVEs Covered](#-known-cves-covered)
  - [🛡️ Mitigation](#️-mitigation)
  - [⚠️ Disclaimer](#️-disclaimer)
  - [📖 References](#-references)
  - [👤 Author](#-author)
  - [📝 License](#-license)
  - [🤝 Contributing](#-contributing)

---

## 🔍 Overview

MinIO is a widely used S3-compatible object storage solution and is often exposed internally or accidentally externally.

This tool assesses a target MinIO instance using supplied credentials and common exposure patterns, surfacing **practical exploitation routes** when misconfigurations are present.

Typical findings include:

- Exposed MinIO console or console API
- Over-privileged S3 credentials
- Admin-level access via `mc`
- Exposed metrics, health, or debug endpoints
- Path traversal vulnerabilities
- Webhook abuse paths (SSRF / callbacks)

> ⚠️ **Authorized testing only.** See [Disclaimer](#-disclaimer).

---

## 🧪 What It Tests

The tool performs the following checks in sequence:

1. **MinIO Console Access**  
   Detects console exposure across common ports.

2. **Console API Authentication**  
   Tests `/api/v1/login` endpoints for token/session acquisition.

3. **S3 API Access**  
   Lists buckets and enumerates objects using `boto3`.

4. **MinIO Client (`mc`) Availability**  
   Checks for `mc`, configures an alias, and validates access.

5. **Admin Privilege Confirmation**  
   Runs `mc admin info` and user listing when permitted.

6. **Exposed Endpoints**  
   Probes metrics, health, and debug endpoints.

7. **Version Detection**  
   Attempts MinIO version extraction from response headers.

8. **Path Traversal Testing**  
   Probes console API traversal patterns (CVE-2024-24747).

9. **Webhook Capability Detection**  
   Verifies webhook config access and prints abuse workflow.

---

## ✨ Features

- Console discovery on common ports
- Console API authentication testing
- S3 bucket and object enumeration
- `mc` client integration
- Admin privilege detection
- Exposed endpoint scanning
- Path traversal probing
- Webhook abuse capability detection
- Color-coded output and final report
- Verbose debugging mode

---

## 📦 Installation

### Requirements

- Python **3.8+**
- `pip`
- Python packages:
  - `requests`
  - `boto3`

### Install dependencies

```bash
pip install requests boto3
```

### (Optional) Install MinIO Client (`mc`)

```bash
wget https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc
sudo mv mc /usr/local/bin/
mc --version
```

---

## 🚀 Usage

### Syntax

```bash
python3 minio_scanner.py -t <target> -p <port> -a <access_key> -s <secret_key> [options]
```

### Options

| Flag | Description | Default |
|-----|------------|---------|
| `-t, --target` | Target hostname or IP | required |
| `-a, --access-key` | Access key | required |
| `-s, --secret-key` | Secret key | required |
| `-p, --port` | MinIO port | 54321 |
| `-b, --bucket` | Target bucket | randomfacts |
| `-v, --verbose` | Verbose output | off |

---

## 📚 Examples

### Standard scan

```bash
python3 minio_scanner.py -t facts.htb -p 54321 -a AKIAxxxx -s SECRET_KEY
```

### Verbose scan with custom bucket

```bash
python3 minio_scanner.py -t 10.10.11.50 -p 9000 -a ACCESS_KEY -s SECRET_KEY -b mybucket -v
```

---

## 📊 Sample Output

```text
[+] MinIO Console FOUND
[+] API Authentication SUCCESSFUL
[+] S3 API Access SUCCESSFUL
[+] mc client available
[+] ADMIN PRIVILEGES CONFIRMED

[CRITICAL] Admin Privileges Confirmed
[HIGH]     S3 API Access Confirmed
[MEDIUM]   Exposed Endpoints Detected
```

---

## 🐛 Known CVEs Covered

| CVE | Category | Notes |
|-----|---------|------|
| CVE-2024-24747 | Path Traversal | Console API traversal patterns |
| CVE-2023-28432 | Info Disclosure | Cluster exposure |
| CVE-2023-28434 | Privilege Escalation | Admin escalation |
| CVE-2021-21287 | Auth Bypass | Historical issue |

> Version-based impact may require manual validation depending on deployment.

---

## 🛡️ Mitigation

**Immediate Actions**
- Restrict access to the MinIO console and APIs
- Rotate credentials and apply least privilege
- Patch MinIO and console components
- Disable debug and public metrics endpoints
- Restrict or disable webhook notifications

**Long-Term Hardening**
- Network segmentation / VPN access
- Dedicated service accounts
- Log and monitor admin operations

---

## ⚠️ Disclaimer

This tool is provided **for authorized security testing and educational purposes only**.

- Only test systems you own or are explicitly authorized to assess
- Unauthorized access may be illegal
- The author assumes no liability for misuse

---

## 📖 References

- https://min.io/docs/
- https://min.io/docs/minio/linux/reference/minio-mc.html
- https://nvd.nist.gov/

---

## 👤 Author

**d3vn0mi**  
GitHub: https://github.com/d3vn0mi

---

## 📝 License

MIT License — see the [LICENSE](LICENSE) file.

---

## 🤝 Contributing

Issues and pull requests are welcome. Please include clear reproduction steps and rationale.
