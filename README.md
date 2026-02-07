# MinIO Security Assessment Tool

```text
     _ _____             ___            _ 
  __| |___ /_   ___ __  / _ \ _ __ ___ (_)
 / _` | |_ \ \ / / '_ \| | | | '_ ` _ \| |
| (_| |___) \ V /| | | | |_| | | | | | | |
 \__,_|____/ \_/ |_| |_|\___/|_| |_| |_|_|
                                                            
minio-scanner v0.1 | github.com/d3vn0mi
```

Comprehensive security assessment & exploitation toolkit for MinIO instances
Console discovery • API auth testing • S3 enumeration • admin validation • endpoint exposure • CVE checks • webhook SSRF paths • reporting

⸻

⚠️ Legal / Ethics

This tool is intended for authorized security testing and educational use only.
Do not run it against systems you do not own or do not have explicit permission to test.

⸻

✨ What it does

🔍 Discovery & Access
	•	Detects MinIO Console (tries common ports)
	•	Tests Console API authentication for token/session acquisition
	•	Validates S3 API access via boto3 using provided credentials
	•	Enumerates buckets and lists sample objects in a target bucket

🛠️ Operator Tooling & Privileges
	•	Checks for MinIO Client (mc) availability
	•	Creates an mc alias (scanner) and validates connectivity
	•	Detects admin privileges
	•	mc admin info
	•	user listing (when permitted)

🌐 Exposed Endpoints

Checks common MinIO endpoints for exposure, including:
	•	Metrics (/minio/metrics, /minio/prometheus/metrics, cluster metrics)
	•	Health (/minio/health/live, /minio/health/ready)
	•	Debug/pprof (/minio/debug/pprof/)

🐞 Vulnerability Checks
	•	Attempts MinIO version identification (via Server header)
	•	Path traversal tests targeting CVE-2024-24747
	•	Prints a curated list of notable historical MinIO CVEs for manual verification

🚀 Exploitation Opportunities (When Misconfigured)
	•	If admin + webhook config accessible:
	•	Shows steps to validate SSRF/callback capability
	•	Provides a basic notification trigger workflow

📊 Reporting
	•	Consolidated findings with severity labels
	•	Practical “next steps” guidance based on what was discovered

⸻

✅ Requirements
	•	Python 3.8+
	•	Python packages:
	•	requests
	•	boto3

Optional (recommended):
	•	MinIO Client (mc) for admin checks and webhook config validation

⸻

📦 Installation

1) Clone

git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>

2) Install Python dependencies

pip install -r requirements.txt

If you don’t use a requirements.txt yet:

pip install requests boto3

3) (Optional) Install mc

wget https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc
sudo mv mc /usr/local/bin/
mc --version


⸻

🚀 Usage

python3 minio_scanner.py \
  -t <TARGET> \
  -p <PORT> \
  -a <ACCESS_KEY> \
  -s <SECRET_KEY> \
  [-b <BUCKET>] \
  [-v]

Arguments

Flag	Description	Default
-t, --target	Target hostname or IP	required
-p, --port	MinIO port	54321
-a, --access-key	Access key	required
-s, --secret-key	Secret key	required
-b, --bucket	Bucket name to enumerate	randomfacts
-v, --verbose	Verbose output (errors/debug)	False


⸻

🧪 Examples

Typical run

python3 minio_scanner.py -t facts.htb -p 54321 -a AKIAxxxx -s SECRETKEY

Verbose + custom bucket

python3 minio_scanner.py -t 10.10.11.50 -p 9000 -a ACCESS_KEY -s SECRET_KEY -b mybucket -v


⸻

🧾 Output Overview

The tool runs a set of tests and ends with a report summarizing:
	•	Console access
	•	API auth status
	•	S3 access & enumeration
	•	mc connectivity
	•	admin privilege confirmation
	•	exposed endpoints
	•	path traversal indicators
	•	webhook configuration access
	•	recommended exploitation paths (contextual)

⸻

🔥 Common Attack Paths (Detected When Applicable)
	•	Admin + Webhook Config → SSRF / callback paths
	•	Console exposure → administrative abuse & misconfiguration exploration
	•	Path traversal → arbitrary file read indicators (CVE-2024-24747)
	•	S3 access → data exposure / object manipulation

⸻

🛡️ Defensive Recommendations (Blue Team)
	•	Restrict or disable public console access
	•	Rotate keys; apply least privilege policies
	•	Patch MinIO and console components regularly
	•	Restrict admin APIs and avoid exposing debug endpoints
	•	Review and lock down webhook notification configs
	•	Place MinIO behind proper network controls (VPN, allowlists, auth gateways)

⸻

👤 Author

d3vn0mi
GitHub: https://github.com/d3vhthnnni

⸻

⚠️ Disclaimer

This project is provided for authorized testing and educational purposes only.
You assume all risk and responsibility for how you use it.

