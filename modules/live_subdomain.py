# Live subdomain checker using httpx/requests
import requests
from urllib.parse import urlparse
import time

def check_live_subdomains(subdomains):
    """Check which subdomains are live (accessible)"""
    live_subdomains = []
    dead_subdomains = []
    
    for subdomain in subdomains:
        # Add http:// if not present
        if not subdomain.startswith(('http://', 'https://')):
            url = f"http://{subdomain}"
        else:
            url = subdomain
        
        try:
            # Try with HTTPS first
            https_url = url.replace('http://', 'https://')
            response = requests.get(https_url, timeout=10, allow_redirects=True)
            
            if response.status_code < 400:
                live_subdomains.append(https_url)
                print(f"[+] Live: {https_url} (Status: {response.status_code})")
                continue
                
        except requests.RequestException:
            pass
        
        try:
            # Fallback to HTTP if HTTPS fails
            response = requests.get(url, timeout=10, allow_redirects=True)
            
            if response.status_code < 400:
                live_subdomains.append(url)
                print(f"[+] Live: {url} (Status: {response.status_code})")
            else:
                dead_subdomains.append(url)
                print(f"[-] Dead: {url} (Status: {response.status_code})")
                
        except requests.RequestException as e:
            dead_subdomains.append(url)
            print(f"[-] Dead: {url} (Error: {str(e)})")
        
        # Small delay to avoid overwhelming servers
        time.sleep(1)
    
    return {
        "live": live_subdomains,
        "dead": dead_subdomains,
        "total_checked": len(subdomains),
        "live_count": len(live_subdomains),
        "dead_count": len(dead_subdomains)
    }