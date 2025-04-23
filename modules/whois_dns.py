import os
import json
import whois
import dns.resolver
from datetime import datetime
from typing import Dict, Any

def create_output_dir() -> None:
    """Create outputs directory if it doesn't exist"""
    if not os.path.exists('outputs'):
        os.makedirs('outputs')
        print("[+] Created 'outputs' directory")

def load_domains(input_file: str) -> list:
    """
    Load domains from input CSV file
    Format: CSV with 'domain' header and one domain per line
    """
    domains = []
    try:
        with open(input_file, 'r') as f:
            # Skip header and read all non-empty lines
            domains = [line.strip() for line in f.readlines()[1:] if line.strip()]
        print(f"[+] Loaded {len(domains)} domains from {input_file}")
    except Exception as e:
        print(f"[-] Error loading domains: {str(e)}")
    return domains

def get_whois_info(domain: str) -> Dict[str, Any]:
    """Perform WHOIS lookup for a domain"""
    result = {'status': 'success', 'data': {}}
    try:
        w = whois.whois(domain)
        
        # Convert datetime objects to strings
        whois_data = {}
        for key, value in w.items():
            if isinstance(value, list):
                whois_data[key] = [str(v) if hasattr(v, 'isoformat') else v for v in value]
            elif hasattr(value, 'isoformat'):
                whois_data[key] = value.isoformat()
            else:
                whois_data[key] = value
        
        result['data'] = whois_data
    except Exception as e:
        result.update({
            'status': 'error',
            'error': str(e)
        })
    return result

def get_dns_records(domain: str) -> Dict[str, Any]:
    """Perform DNS lookups for common record types"""
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
    result = {'status': 'success', 'data': {}}
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            result['data'][record_type] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            result['data'][record_type] = []
        except dns.resolver.NXDOMAIN:
            result.update({
                'status': 'error',
                'error': f"Domain {domain} does not exist"
            })
            break
        except Exception as e:
            result['data'][record_type] = []
            print(f"[-] Error getting {record_type} record for {domain}: {str(e)}")
    
    return result

def save_results(domain: str, whois_data: Dict[str, Any], dns_data: Dict[str, Any]) -> None:
    """Save combined WHOIS and DNS results to JSON file"""
    output = {
        'domain': domain,
        'timestamp': datetime.now().isoformat(),
        'whois': whois_data,
        'dns': dns_data
    }
    
    filename = f"outputs/{domain}_whois_dns.json"
    try:
        with open(filename, 'w') as f:
            json.dump(output, f, indent=4)
        print(f"[+] Saved results for {domain} to {filename}")
    except Exception as e:
        print(f"[-] Error saving results for {domain}: {str(e)}")

def process_domain(domain: str) -> None:
    """Process a single domain through WHOIS and DNS lookups"""
    print(f"\n🔍 Processing domain: {domain}")
    
    # WHOIS lookup
    print(f"[+] Performing WHOIS lookup...")
    whois_info = get_whois_info(domain)
    if whois_info['status'] == 'error':
        print(f"[-] WHOIS lookup failed: {whois_info['error']}")
    
    # DNS lookup
    print(f"[+] Performing DNS lookups...")
    dns_info = get_dns_records(domain)
    if dns_info['status'] == 'error':
        print(f"[-] DNS lookup failed: {dns_info['error']}")
    
    # Save results
    save_results(domain, whois_info, dns_info)

def main(input_file: str) -> None:
    """Main function to process all domains"""
    print("\n🚀 Starting WHOIS and DNS Lookup Tool")
    print(f"Input file: {input_file}")
    print(f"Timestamp: {datetime.now().isoformat()}\n")
    
    create_output_dir()
    domains = load_domains(input_file)
    
    if not domains:
        print("[-] No domains to process")
        return
    
    for domain in domains:
        process_domain(domain)
    
    print("\n✅ All domains processed successfully")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python whois_dns.py input.csv")
        sys.exit(1)
    
    main(sys.argv[1])