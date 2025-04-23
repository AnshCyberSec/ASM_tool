from datetime import datetime
import sys
import time
import json
import os
import google.generativeai as genai
from typing import Any, Dict
from urllib.parse import urlparse
from modules.subdomain import find_subdomains  # Make sure this matches your actual function name
from modules.live_subdomain import check_live_subdomains
from modules.port_scan import scan_subdomains
from modules.ssl_analysis import analyze_ssl
from modules.headers import analyze_headers, save_header_results, print_summary
from modules.sensitive_paths import scan_sensitive_paths, save_sensitive_paths_results, print_sensitive_paths_summary
from modules.whois_dns import main as whois_dns_scan
from modules.osint import main as osint_scan, save_results
from modules.ai_analysis import generate_risk_summary, save_ai_results
from dotenv import load_dotenv
from typing import Dict, Any
from modules.ai_analysis import generate_risk_summary, save_ai_results
from modules.tech_stack import tech_stack_scan
from modules.tech_stack import main as tech_stack_scan




def show_banner():
    """Displays the tool's ASCII banner"""
    try:
        banner = r"""
        █████╗ ███████╗███╗   ███╗    ████████╗ ██████╗  ██████╗ ██╗
        ██╔══██╗██╔════╝████╗ ████║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║
        ███████║███████╗██╔████╔██║       ██║   ██║   ██║██║   ██║██║
        ██╔══██║╚════██║██║╚██╔╝██║       ██║   ██║   ██║██║   ██║██║
        ██║  ██║███████║██║ ╚═╝ ██║       ██║   ╚██████╔╝╚██████╔╝███████╗
        ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
        """
        print(banner)
        print("    Automated Security Monitoring Tool")
        print("    Developed by: Anshuman Dalabehera")
        print("    Organization: Cybtree\n")
        time.sleep(1)
    except:
        # Fallback to simple ASCII if there's any error
        print("\n=== ASM TOOL ===")
        print("By Anshuman Dalabehera")
        print("CyberTree Internship\n")

def load_domains(file_path):
    """Loads domains from file with automatic encoding detection"""
    encodings = ['utf-8', 'utf-8-sig', 'utf-16']  # Supported encodings
    
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                domains = [line.strip() for line in f 
                        if line.strip() and not line.startswith(('domain', '#'))]
                
                if domains:
                    print(f"[+] Loaded {len(domains)} domains")
                    return domains
        except (UnicodeError, IOError) as e:
            continue
    
    print("[X] Error: Failed to read domains file")
    return None

def save_result(domain, data):
    """Saves subdomains to JSON file"""
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, f"{domain}_subdomains.json")
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"[+] Subdomains saved to {filepath}")

def save_live_results(domain, data):
    """Saves live/dead subdomains to JSON file"""
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, f"{domain}_live_subdomains.json")
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"[+] Live/Dead results saved to {filepath}")

def save_port_scan_results(domain, data):
    """Saves port scan results to JSON file"""
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, f"{domain}_port_scan.json")
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"[+] Port scan results saved to {filepath}")

def load_live_subdomains(domain):
    """Load live subdomains from JSON file"""
    filepath = os.path.join("outputs", f"{domain}_live_subdomains.json")
    
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            return data.get("live", [])
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[X] Error loading live subdomains: {e}")
        return None



def save_ssl_results(domain, data):
    """Saves SSL analysis results to JSON file"""
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, f"{domain}_ssl_analysis.json")
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"[+] SSL analysis results saved to {filepath}")

def load_port_scan_results(domain):
    """Load port scan results and filter subdomains with port 443 open"""
    filepath = os.path.join("outputs", f"{domain}_port_scan.json")
    
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            return [
                subdomain for subdomain, info in data.items() 
                if info['status'] == 'active' and 443 in info['open_ports']
            ]
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[X] Error loading port scan results: {e}")
        return None
# Add this helper function to collect scan results
def collect_scan_results(domain: str) -> Dict[str, Any]:
    """Gather all scan results for a domain"""
    results = {"domain": domain}
    
    # List of all possible scan types and their file suffixes
    scan_types = [
        ("subdomains", "_subdomains.json"),
        ("live", "_live_subdomains.json"),
        ("ports", "_port_scan.json"),
        ("ssl", "_ssl_analysis.json"),
        ("headers", "_headers.json"),
        ("paths", "_sensitive_paths.json"),
        ("whois", "_whois_dns.json"),
        ("osint", "_osint.json"),
        ("tech", "_tech_stack.json")
    ]
    
    for name, suffix in scan_types:
        filepath = f"outputs/{domain}{suffix}"
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    results[name] = json.load(f)
            except Exception as e:
                print(f"⚠️ Error loading {name} scan: {str(e)}")
                results[name] = {"error": str(e)}
    
    return results

def main():
    load_dotenv()
    show_banner()
    
    if len(sys.argv) != 3 or sys.argv[1] != "--input":
        print("\nUsage: python main.py --input domains.csv")
        return
    
    domains = load_domains(sys.argv[2])
    if not domains:
        return
        
        
    print("\n🚀 Starting subdomain enumeration...")

    # First run WHOIS/DNS scan on the root domains
    print("\n🔍 Starting WHOIS and DNS scan for root domains...")
    whois_dns_scan(sys.argv[2])  # This processes the input.csv file directly

    # Technology Stack Detection - Add this section
    print("\n[🛠️] Starting Technology Stack Detection...")
    try:
        tech_stack_scan(sys.argv[2])  # This should process the input CSV
        print("[✅] Technology stack detection completed")
    except Exception as e:
        print(f"[❌] Technology stack detection failed: {str(e)}")
    # NEW CODE ENDS HERE


    # OSINT Scanning (NEW CODE STARTS HERE)
    print("\n[🕵️] Starting OSINT scanning for root domains...")
    osint_scan(sys.argv[2])  # This processes the input.csv file directly
    # NEW CODE ENDS HERE
    
    

    for domain in domains:
        # Perform subdomain enumeration
        subdomains = find_subdomains(domain)
        
        if not subdomains:
            print(f"[!] No subdomains found for {domain}")
            continue
            
        # Save raw subdomains
        save_result(domain, subdomains)
        
        # Check live subdomains
        print(f"\n🔍 Checking live subdomains for {domain}...")
        live_results = check_live_subdomains(subdomains)
        
        # Save live/dead results
        save_live_results(domain, live_results)
        
        # Print summary
        print(f"\n📊 Summary for {domain}:")
        print(f"Total subdomains checked: {live_results['total_checked']}")
        print(f"Live subdomains: {live_results['live_count']}")
        print(f"Dead subdomains: {live_results['dead_count']}")
        
        # Port scanning for live subdomains
        if live_results['live_count'] > 0:
            print(f"\n🔦 Starting port scanning for live subdomains...")
            live_subdomains = load_live_subdomains(domain)
            
            if live_subdomains:
                port_scan_results = scan_subdomains(live_subdomains)
                save_port_scan_results(domain, port_scan_results)
                
                # Print port scan summary
                print("\n📌 Port Scan Summary:")
                for subdomain, data in port_scan_results.items():
                    if data['open_ports']:
                        print(f"🌐 {subdomain} - Open ports: {', '.join(map(str, data['open_ports']))}")
                    else:
                        print(f"🌐 {subdomain} - No open ports found")
                
                # SSL/TLS analysis for subdomains with port 443 open
                ssl_subdomains = load_port_scan_results(domain)
                if ssl_subdomains:
                    print(f"\n🔐 Starting SSL/TLS analysis for {len(ssl_subdomains)} subdomains with port 443 open...")
                    ssl_results = analyze_ssl(ssl_subdomains)
                    save_ssl_results(domain, ssl_results)
                    
                    # Print SSL summary
                    print("\n🔍 SSL/TLS Analysis Summary:")
                    valid_certs = sum(1 for res in ssl_results.values() if res.get('is_valid', False))
                    expiring_soon = sum(1 for res in ssl_results.values() if res.get('days_remaining', 0) < 30)
                    weak_ssl = sum(1 for res in ssl_results.values() if res.get('is_weak', False))
                    
                    print(f"✅ Valid certificates: {valid_certs}/{len(ssl_results)}")
                    print(f"⚠️  Expiring soon (<30 days): {expiring_soon}")
                    print(f"❌ Weak protocols (TLSv1/TLSv1.1): {weak_ssl}")

                    # HTTP Security Header Analysis
                    print(f"\n🛡️ Starting HTTP Security Header Analysis...")
                    header_results = analyze_headers(ssl_subdomains)
                    save_header_results(domain, header_results)
                    print_summary(header_results)
                    
                    # Sensitive Paths Scanning
                    print(f"\n🔎 Starting sensitive paths scanning...")
                    clean_subdomains = [urlparse(s).netloc if s.startswith('http') else s.split('/')[0] 
                                    for s in ssl_subdomains]
                    sensitive_paths_results = scan_sensitive_paths(clean_subdomains)
                    save_sensitive_paths_results(domain, sensitive_paths_results)
                    print_sensitive_paths_summary(sensitive_paths_results)

                    # AI Risk Analysis
                    print(f"\n🤖 Generating AI-Powered Risk Summary for {domain}...")

                    # Collect all existing scan results
                    scan_results = collect_scan_results(domain)

                    # Generate and save AI analysis
                    try:
                        ai_results = generate_risk_summary(domain, scan_results)
                        save_ai_results(domain, ai_results)
    
                        # Print results
                        if "analysis" in ai_results:
                            analysis = ai_results["analysis"]
                            print("\n📋 Risk Assessment Summary:")
                            print(f"Severity: {analysis.get('severity', 'Unknown')}")
                            print(f"Summary: {analysis.get('summary', 'No summary available')}")
                            print("\n🔧 Recommendations:")
                            for i, rec in enumerate(analysis.get("recommendations", []), 1):
                                print(f"{i}. {rec}")
                        else:
                            print("❌ No analysis generated due to errors")

                    except Exception as e:
                        print(f"❌ Failed to generate AI analysis: {str(e)}")
        
            print(f"\n✅ Completed processing for {domain}")

    print("\n🎉 All operations completed successfully!")

if __name__ == "__main__":
    main()