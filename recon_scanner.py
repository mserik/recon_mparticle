#!/usr/bin/env python3
"""
Light, non-intrusive reconnaissance scanner for authorized security assessment.
Performs DNS resolution, basic port checks, and HTTP/HTTPS fingerprinting.
"""

import socket
import requests
import pandas as pd
import re
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Tuple, Optional
import time
from bs4 import BeautifulSoup
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Configuration
INPUT_FILE = 'recon.txt'
OUTPUT_CSV = 'recon_results.csv'
OUTPUT_MD = 'recon_results.md'

# Ports to check
PORTS_TO_SCAN = [80, 443, 8080, 8443, 22, 25, 53, 3306, 5432]
WEB_PORTS = [80, 443, 8080, 8443]

# Timeouts
DNS_TIMEOUT = 5
TCP_TIMEOUT = 3
HTTP_TIMEOUT = 10

# Request settings
MAX_REDIRECTS = 3
USER_AGENT = 'Mozilla/5.0 (Security Assessment - Authorized)'


def parse_subdomains(filename: str) -> List[str]:
    """Parse and deduplicate subdomains from input file."""
    subdomains = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                subdomain = line.strip()
                if subdomain and subdomain not in subdomains:
                    subdomains.append(subdomain)
        print(f"[+] Loaded {len(subdomains)} unique subdomains from {filename}")
        return subdomains
    except Exception as e:
        print(f"[!] Error reading {filename}: {e}")
        return []


def resolve_dns(subdomain: str) -> List[str]:
    """Resolve subdomain to IP addresses (A/AAAA records)."""
    ips = []
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        addr_info = socket.getaddrinfo(subdomain, None)
        for info in addr_info:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except socket.gaierror:
        return []
    except Exception as e:
        print(f"[!] DNS resolution error for {subdomain}: {e}")
        return []


def check_port(ip: str, port: int, timeout: int = TCP_TIMEOUT) -> bool:
    """Quick TCP connect check for a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_ports(subdomain: str, ips: List[str]) -> List[int]:
    """Scan common ports on the first resolved IP."""
    if not ips:
        return []

    # Use first IP for port scanning
    ip = ips[0]
    open_ports = []

    for port in PORTS_TO_SCAN:
        if check_port(ip, port):
            open_ports.append(port)

    return open_ports


def extract_title(html: str) -> str:
    """Extract HTML title tag."""
    try:
        soup = BeautifulSoup(html, 'html.parser')
        title_tag = soup.find('title')
        if title_tag:
            return title_tag.get_text().strip()[:200]
        return ''
    except Exception:
        return ''


def detect_tech_stack(headers: dict, html: str, url: str) -> Dict[str, str]:
    """Detect technology stack from headers and HTML."""
    tech = {
        'server': headers.get('Server', '').split('/')[0] if headers.get('Server') else '',
        'powered_by': headers.get('X-Powered-By', ''),
        'framework': '',
        'cms': ''
    }

    # Framework detection from HTML
    html_lower = html.lower()
    if 'react' in html_lower or '__react' in html_lower:
        tech['framework'] = 'React'
    elif 'angular' in html_lower or 'ng-' in html_lower:
        tech['framework'] = 'Angular'
    elif 'next.js' in html_lower or '__next' in html_lower:
        tech['framework'] = 'Next.js'
    elif 'vue.js' in html_lower or 'vue' in html_lower:
        tech['framework'] = 'Vue.js'

    # Server detection enhancement
    server_header = headers.get('Server', '').lower()
    if 'nginx' in server_header:
        tech['server'] = 'nginx'
    elif 'apache' in server_header:
        tech['server'] = 'Apache'
    elif 'iis' in server_header:
        tech['server'] = 'IIS'
    elif 'cloudflare' in server_header:
        tech['server'] = 'Cloudflare'

    return tech


def classify_endpoint(subdomain: str, title: str, html: str, headers: dict, status: int) -> Dict[str, any]:
    """Classify endpoint type and flag interesting characteristics."""
    classification = {
        'type': 'unknown',
        'is_auth': False,
        'is_api': False,
        'is_admin': False,
        'is_static': False,
        'notes': []
    }

    subdomain_lower = subdomain.lower()
    title_lower = title.lower() if title else ''
    html_lower = html.lower()

    # Subdomain-based classification
    if 'api' in subdomain_lower:
        classification['type'] = 'API'
        classification['is_api'] = True
    if 'auth' in subdomain_lower or 'idp' in subdomain_lower or 'identity' in subdomain_lower:
        classification['type'] = 'Auth/SSO'
        classification['is_auth'] = True
    if 'admin' in subdomain_lower or 'panel' in subdomain_lower:
        classification['type'] = 'Admin'
        classification['is_admin'] = True
    if 'tracking' in subdomain_lower:
        classification['type'] = 'Tracking/Analytics'
    if 'sdk' in subdomain_lower:
        classification['type'] = 'SDK Delivery'

    # Title/content-based classification
    if any(x in title_lower for x in ['admin', 'dashboard', 'panel', 'console']):
        classification['is_admin'] = True
        classification['notes'].append('Admin/Dashboard keywords in title')

    if any(x in title_lower for x in ['login', 'sign in', 'auth']):
        classification['is_auth'] = True
        classification['notes'].append('Login page detected')

    # Interesting findings
    if status == 401:
        classification['notes'].append('⚠️ 401 Unauthorized on root')
    elif status == 403:
        classification['notes'].append('⚠️ 403 Forbidden on root')
    elif status == 404:
        classification['notes'].append('404 on root path')

    if any(x in html_lower for x in ['default page', 'it works', 'apache2 ubuntu', 'nginx welcome']):
        classification['notes'].append('🚩 Default web server page detected')

    if any(x in html_lower for x in ['debug', 'stack trace', 'exception', 'error']):
        classification['notes'].append('🚩 Debug/error information visible')

    if 'set-cookie' in str(headers).lower():
        cookies = headers.get('Set-Cookie', '')
        if 'secure' not in cookies.lower():
            classification['notes'].append('⚠️ Cookies without Secure flag')

    # Check for common framework/CMS
    if 'wordpress' in html_lower or 'wp-content' in html_lower:
        classification['notes'].append('WordPress detected')

    return classification


def probe_http(subdomain: str, port: int, use_https: bool = False) -> Optional[Dict]:
    """Probe a web port with HTTP/HTTPS."""
    protocol = 'https' if use_https else 'http'
    url = f"{protocol}://{subdomain}:{port}/" if port not in [80, 443] else f"{protocol}://{subdomain}/"

    try:
        response = requests.get(
            url,
            headers={'User-Agent': USER_AGENT},
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
            verify=False,  # Don't verify SSL certs for recon
            max_redirects=MAX_REDIRECTS
        )

        # Extract headers
        headers_dict = dict(response.headers)

        # Extract title and tech
        html = response.text[:50000]  # Limit HTML to first 50KB
        title = extract_title(html)
        tech = detect_tech_stack(headers_dict, html, response.url)
        classification = classify_endpoint(subdomain, title, html, headers_dict, response.status_code)

        return {
            'protocol': protocol,
            'port': port,
            'status': response.status_code,
            'final_url': response.url,
            'title': title,
            'server': headers_dict.get('Server', ''),
            'content_type': headers_dict.get('Content-Type', ''),
            'x_powered_by': headers_dict.get('X-Powered-By', ''),
            'tech_stack': tech,
            'classification': classification,
            'redirect_count': len(response.history)
        }
    except requests.exceptions.SSLError:
        return None
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.ConnectionError:
        return None
    except Exception as e:
        return None


def scan_web_services(subdomain: str, open_ports: List[int]) -> List[Dict]:
    """Scan web services on open web ports."""
    results = []

    for port in open_ports:
        if port not in WEB_PORTS:
            continue

        # Try HTTPS first for 443 and 8443
        if port in [443, 8443]:
            result = probe_http(subdomain, port, use_https=True)
            if result:
                results.append(result)
                continue

        # Try HTTP
        result = probe_http(subdomain, port, use_https=False)
        if result:
            results.append(result)
        # If HTTP failed on 443/8443, still try HTTPS
        elif port in [443, 8443]:
            result = probe_http(subdomain, port, use_https=True)
            if result:
                results.append(result)

    return results


def scan_subdomain(subdomain: str) -> Dict:
    """Complete scan of a single subdomain."""
    print(f"[*] Scanning {subdomain}...")

    # DNS Resolution
    ips = resolve_dns(subdomain)

    if not ips:
        return {
            'subdomain': subdomain,
            'resolved_ips': '',
            'open_ports': '',
            'http_status': '',
            'final_url': '',
            'title': '',
            'server': '',
            'x_powered_by': '',
            'tech_guess': '',
            'endpoint_type': '',
            'notes': 'DNS resolution failed'
        }

    # Port scanning
    open_ports = scan_ports(subdomain, ips)

    if not open_ports:
        return {
            'subdomain': subdomain,
            'resolved_ips': ', '.join(ips),
            'open_ports': '',
            'http_status': '',
            'final_url': '',
            'title': '',
            'server': '',
            'x_powered_by': '',
            'tech_guess': '',
            'endpoint_type': '',
            'notes': 'No open ports detected'
        }

    # Web service fingerprinting
    web_results = scan_web_services(subdomain, open_ports)

    # Aggregate results
    if web_results:
        # Use first successful web result
        web = web_results[0]
        tech = web['tech_stack']
        classification = web['classification']

        tech_parts = []
        if tech['server']:
            tech_parts.append(tech['server'])
        if tech['powered_by']:
            tech_parts.append(tech['powered_by'])
        if tech['framework']:
            tech_parts.append(tech['framework'])

        notes = classification.get('notes', [])
        if len(web_results) > 1:
            notes.append(f"{len(web_results)} web services detected")

        return {
            'subdomain': subdomain,
            'resolved_ips': ', '.join(ips),
            'open_ports': ', '.join(map(str, open_ports)),
            'http_status': str(web['status']),
            'final_url': web['final_url'],
            'title': web['title'],
            'server': tech['server'],
            'x_powered_by': tech['powered_by'],
            'tech_guess': ', '.join(tech_parts) if tech_parts else 'Unknown',
            'endpoint_type': classification.get('type', 'Unknown'),
            'notes': ' | '.join(notes) if notes else ''
        }
    else:
        # No web services responded
        non_web_ports = [p for p in open_ports if p not in WEB_PORTS]
        notes = []
        if non_web_ports:
            notes.append(f"Non-web ports open: {', '.join(map(str, non_web_ports))}")

        return {
            'subdomain': subdomain,
            'resolved_ips': ', '.join(ips),
            'open_ports': ', '.join(map(str, open_ports)),
            'http_status': '',
            'final_url': '',
            'title': '',
            'server': '',
            'x_powered_by': '',
            'tech_guess': '',
            'endpoint_type': 'Non-HTTP',
            'notes': ' | '.join(notes) if notes else 'Web ports did not respond'
        }


def main():
    """Main execution flow."""
    print("=" * 70)
    print("  AUTHORIZED SECURITY RECONNAISSANCE SCANNER")
    print("=" * 70)
    print()

    # Parse input
    subdomains = parse_subdomains(INPUT_FILE)
    if not subdomains:
        print("[!] No subdomains to scan. Exiting.")
        return

    print(f"[+] Starting scan of {len(subdomains)} subdomains")
    print(f"[+] Ports to check: {', '.join(map(str, PORTS_TO_SCAN))}")
    print()

    # Scan all subdomains
    results = []
    start_time = time.time()

    # Sequential scanning with small delay to be polite
    for subdomain in subdomains:
        result = scan_subdomain(subdomain)
        results.append(result)
        time.sleep(0.5)  # Small delay between hosts

    elapsed = time.time() - start_time
    print()
    print(f"[+] Scan completed in {elapsed:.2f} seconds")
    print()

    # Create DataFrame
    df = pd.DataFrame(results)

    # Save results
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"[+] Results saved to {OUTPUT_CSV}")

    # Save Markdown
    with open(OUTPUT_MD, 'w') as f:
        f.write("# Reconnaissance Results\n\n")
        f.write(f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Total Subdomains:** {len(subdomains)}\n\n")
        f.write("## Findings\n\n")
        f.write(df.to_markdown(index=False))
    print(f"[+] Markdown report saved to {OUTPUT_MD}")
    print()

    # Print summary
    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print()

    # DNS failures
    dns_failed = df[df['resolved_ips'] == '']
    if len(dns_failed) > 0:
        print(f"[!] {len(dns_failed)} subdomain(s) failed DNS resolution:")
        for _, row in dns_failed.iterrows():
            print(f"    - {row['subdomain']}")
        print()

    # No response hosts
    no_ports = df[(df['resolved_ips'] != '') & (df['open_ports'] == '')]
    if len(no_ports) > 0:
        print(f"[!] {len(no_ports)} subdomain(s) with no open ports:")
        for _, row in no_ports.iterrows():
            print(f"    - {row['subdomain']} ({row['resolved_ips']})")
        print()

    # Interesting findings
    interesting = df[df['notes'].str.contains('⚠️|🚩', na=False, regex=True)]
    if len(interesting) > 0:
        print(f"[!] {len(interesting)} subdomain(s) with interesting findings:")
        for _, row in interesting.iterrows():
            print(f"    - {row['subdomain']}: {row['notes']}")
        print()

    # Unexpected ports (non-web)
    unexpected_ports = df[df['notes'].str.contains('Non-web ports', na=False)]
    if len(unexpected_ports) > 0:
        print(f"[!] {len(unexpected_ports)} subdomain(s) with unexpected open ports:")
        for _, row in unexpected_ports.iterrows():
            print(f"    - {row['subdomain']}: {row['notes']}")
        print()

    # Auth/Admin endpoints
    sensitive = df[df['endpoint_type'].str.contains('Auth|Admin', na=False, regex=True)]
    if len(sensitive) > 0:
        print(f"[+] {len(sensitive)} Auth/Admin endpoint(s) detected:")
        for _, row in sensitive.iterrows():
            print(f"    - {row['subdomain']} ({row['endpoint_type']}): {row['title']}")
        print()

    # API endpoints
    apis = df[df['endpoint_type'].str.contains('API', na=False)]
    if len(apis) > 0:
        print(f"[+] {len(apis)} API endpoint(s) detected:")
        for _, row in apis.iterrows():
            status = f" [{row['http_status']}]" if row['http_status'] else ""
            print(f"    - {row['subdomain']}{status}")
        print()

    print("=" * 70)
    print(f"[+] Full results available in {OUTPUT_CSV} and {OUTPUT_MD}")
    print("=" * 70)


if __name__ == '__main__':
    main()
