import os
import json
import httpx
from datetime import datetime
from typing import Dict, Any
import csv
import time

def create_output_dir() -> None:
    """Create outputs directory if it doesn't exist"""
    if not os.path.exists('outputs'):
        os.makedirs('outputs')
        print("[+] Created 'outputs' directory")

def load_domains(input_file: str) -> list:
    """Load domains from input CSV file"""
    domains = []
    try:
        with open(input_file, 'r') as f:
            reader = csv.DictReader(f)
            domains = [row['domain'].strip() for row in reader if row['domain'].strip()]
        print(f"[+] Loaded {len(domains)} domains from {input_file}")
    except Exception as e:
        print(f"[-] Error loading domains: {str(e)}")
    return domains

def check_breaches(domain: str) -> Dict[str, Any]:
    """Check domain against breach databases (simulated)"""
    print(f"[🔍] Checking breaches for {domain}...")
    
    # Simulated breach data - replace with actual API calls if you have access
    # Example using HaveIBeenPwned would require API key:
    # response = httpx.get(f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}")
    
    # Simulated response
    time.sleep(1)  # Simulate API delay
    return {
        "status": "success",
        "breaches": [
            {
                "name": "ExampleBreach2023",
                "date": "2023-03-15",
                "data_classes": ["emails", "passwords"],
                "description": "Simulated breach data - replace with real API call"
            }
        ],
        "note": "Using simulated data. For real results, integrate with HaveIBeenPwned API"
    }

def check_github_leaks(domain: str) -> Dict[str, Any]:
    """Check for domain in GitHub code leaks (simulated)"""
    print(f"[⌨️] Checking GitHub leaks for {domain}...")
    
    # Simulated response - real implementation would use GitHub API
    time.sleep(1)
    return {
        "status": "success",
        "leaks": [
            {
                "repository": "example/user-repo",
                "file_path": "config/database.yml",
                "found_strings": [f"DB_HOST={domain}"],
                "note": "Simulated data - real implementation needs GitHub API access"
            }
        ]
    }

def check_pastebin_dumps(domain: str) -> Dict[str, Any]:
    """Check for domain in pastebin dumps (simulated)"""
    print(f"[📋] Checking pastebin dumps for {domain}...")
    
    # Simulated response
    time.sleep(0.5)
    return {
        "status": "success",
        "results": [
            {
                "source": "Pastebin Simulated",
                "url": "https://pastebin.com/abc123",
                "date": "2024-01-10",
                "matches": [f"admin@{domain}", f"db.{domain}"]
            }
        ],
        "note": "Simulated data - real implementation needs Pastebin API"
    }

def save_results(domain: str, data: Dict[str, Any]) -> None:
    """Save OSINT results to JSON file"""
    filename = f"outputs/{domain}_osint.json"
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[💾] Saved OSINT results for {domain} to {filename}")
    except Exception as e:
        print(f"[-] Error saving results for {domain}: {str(e)}")

def scan_domain(domain: str) -> Dict[str, Any]:
    """Perform full OSINT scan for a single domain"""
    print(f"\n[🌐] Starting OSINT scan for {domain}")
    
    results = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "breaches": check_breaches(domain),
        "github_leaks": check_github_leaks(domain),
        "pastebin_dumps": check_pastebin_dumps(domain),
        "notes": [
            "This is simulated data. For real results:",
            "1. Register for HaveIBeenPwned API",
            "2. Get GitHub API token",
            "3. Use Pastebin API or services like DeHashed"
        ]
    }
    
    save_results(domain, results)
    return results

def main(input_file: str) -> None:
    """Main function to process all domains"""
    print("\n[🚀] Starting OSINT Scanner")
    print(f"Input file: {input_file}")
    print(f"Timestamp: {datetime.now().isoformat()}\n")
    
    create_output_dir()
    domains = load_domains(input_file)
    
    if not domains:
        print("[❌] No domains to process")
        return
    
    for domain in domains:
        scan_domain(domain)
    
    print("\n[✅] All OSINT scans completed!")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python osint.py input.csv")
        sys.exit(1)
    
    main(sys.argv[1])