import os
import json
import csv
import subprocess
from datetime import datetime
from urllib.parse import urlparse
import httpx
import sys

def create_output_dir():
    """Create outputs directory if it doesn't exist"""
    if not os.path.exists('outputs'):
        os.makedirs('outputs')
        print("[+] Created 'outputs' directory")

def load_domains(input_file):
    """Load domains from input CSV file"""
    domains = []
    try:
        with open(input_file, 'r') as f:
            reader = csv.DictReader(f)
            domains = [row['domain'].strip() for row in reader if 'domain' in row and row['domain'].strip()]
        print(f"[+] Loaded {len(domains)} domains from {input_file}")
        return domains
    except Exception as e:
        print(f"[-] Error loading domains: {str(e)}")
        return []

def normalize_domain(domain):
    """Ensure domain has proper format and return clean version"""
    if not domain.startswith(('http://', 'https://')):
        domain = f'https://{domain}'
    return domain, urlparse(domain).netloc

def detect_with_whatweb(domain):
    """Detect tech stack using locally cloned WhatWeb via Ruby"""
    try:
        script_path = os.path.join(os.path.dirname(__file__), 'WhatWeb', 'whatweb')
        result = subprocess.run(
            ['ruby', script_path, '--color=never', '--log-json=-', domain],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            print(f"[-] WhatWeb error output:\n{result.stderr}")
    except FileNotFoundError:
        print("[!] WhatWeb script not found. Ensure it's cloned inside 'modules/WhatWeb/'")
    except Exception as e:
        print(f"[-] WhatWeb exception: {str(e)}")
    return None

def detect_with_http(domain):
    """Enhanced HTTP detection with more technology fingerprints"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        with httpx.Client(timeout=15, follow_redirects=True, http2=True) as client:
            response = client.get(domain, headers=headers)
            tech_stack = {
                'url': str(response.url),
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'technologies': []
            }

            text = response.text.lower()
            headers_str = str(response.headers).lower()

            patterns = [
                # CMS
                ('wordpress', 'WordPress', 'CMS'),
                ('wp-content', 'WordPress', 'CMS'),
                ('joomla', 'Joomla', 'CMS'),
                ('drupal', 'Drupal', 'CMS'),
                ('shopify', 'Shopify', 'E-commerce'),
                ('magento', 'Magento', 'E-commerce'),
                
                # JS Frameworks
                ('react', 'React', 'JavaScript Framework'),
                ('vue.js', 'Vue.js', 'JavaScript Framework'),
                ('angular', 'Angular', 'JavaScript Framework'),
                
                # Web Servers
                ('nginx', 'NGINX', 'Web Server'),
                ('apache', 'Apache', 'Web Server'),
                ('iis', 'IIS', 'Web Server'),
                ('cloudflare', 'Cloudflare', 'CDN'),
                
                # Programming Languages
                ('php', 'PHP', 'Programming Language'),
                ('asp.net', 'ASP.NET', 'Framework'),
                ('laravel', 'Laravel', 'PHP Framework'),
                
                # Analytics
                ('google-analytics', 'Google Analytics', 'Analytics'),
                ('gtm.js', 'Google Tag Manager', 'Analytics'),
                
                # Security
                ('hsts', 'HSTS', 'Security Header'),
                ('csp', 'Content Security Policy', 'Security Header')
            ]

            for pattern, name, tech_type in patterns:
                if pattern in text or pattern in headers_str:
                    tech_stack['technologies'].append({
                        'name': name,
                        'type': tech_type,
                        'confidence': 'high' if pattern in headers_str else 'medium'
                    })

            return tech_stack
            
    except Exception as e:
        print(f"[-] HTTP detection error for {domain}: {str(e)}")
        return None

def save_results(clean_domain, data):
    """Save technology stack results to JSON file"""
    filename = f"outputs/{clean_domain}_tech_stack.json"
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[+] Saved results to {filename}")
        return True
    except Exception as e:
        print(f"[-] Error saving results: {str(e)}")
        return False

def scan_domain(domain):
    """Perform technology detection for a single domain"""
    full_domain, clean_domain = normalize_domain(domain)
    print(f"\n[🔍] Scanning {full_domain}...")

    tech_data = detect_with_whatweb(full_domain) or detect_with_http(full_domain)

    if tech_data:
        results = {
            'domain': clean_domain,
            'timestamp': datetime.now().isoformat(),
            'data': tech_data,
            'detection_method': 'whatweb' if 'target' in tech_data else 'http'
        }
        if save_results(clean_domain, results):
            return results
    else:
        print(f"[❌] Failed to detect tech stack for {clean_domain}")
    return None

def tech_stack_scan(input_file):
    """Main function to process all domains (entry point for module)"""
    print("\n[🚀] Starting Technology Stack Detection")
    print(f"Input file: {input_file}")
    print(f"Timestamp: {datetime.now().isoformat()}")

    create_output_dir()
    domains = load_domains(input_file)

    if not domains:
        print("[❌] No valid domains found in input file")
        return False

    results = []
    for domain in domains:
        result = scan_domain(domain)
        if result:
            results.append(result)

    print(f"\n[✅] Completed! Processed {len(results)}/{len(domains)} domains successfully")
    return len(results) > 0

def main(input_file):
    """Alias for tech_stack_scan for backward compatibility"""
    return tech_stack_scan(input_file)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tech_stack.py input.csv")
        sys.exit(1)

    tech_stack_scan(sys.argv[1])
