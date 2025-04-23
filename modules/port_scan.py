import socket
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports to scan (Top 50 most common ports + some web ports)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 
    143, 443, 445, 993, 995, 1723, 3306, 3389, 
    5900, 8080, 8443, 8888, 9000, 9001, 27017,
    # Additional web ports
    81, 3000, 3001, 4000, 5000, 5432, 6379,
    8000, 8001, 8008, 8010, 8081, 8082, 8090,
    8880, 9090, 9200, 9300
]

def scan_port(hostname, port, timeout=1):
    """Scan a single port on a host"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((hostname, port))
            if result == 0:
                return port
    except (socket.gaierror, socket.timeout, ConnectionRefusedError):
        pass
    return None

def scan_ports(hostname, ports=None, max_threads=50):
    """Scan multiple ports on a host using threading"""
    if ports is None:
        ports = COMMON_PORTS
    
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, hostname, port): port for port in ports}
        
        for future in as_completed(futures):
            port = futures[future]
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
            except Exception as e:
                print(f"Error scanning port {port} on {hostname}: {e}")
    
    return sorted(open_ports)

def scan_subdomains(subdomains):
    """Scan ports for multiple subdomains"""
    results = {}
    
    for subdomain in subdomains:
        # Extract hostname from URL
        if subdomain.startswith(('http://', 'https://')):
            hostname = subdomain.split('//')[1].split('/')[0]
        else:
            hostname = subdomain.split('/')[0]
        
        print(f"🔍 Scanning {hostname}...")
        open_ports = scan_ports(hostname)
        
        if open_ports:
            print(f"✅ Found {len(open_ports)} open ports on {hostname}")
            results[subdomain] = {
                "hostname": hostname,
                "open_ports": open_ports,
                "status": "active"
            }
        else:
            print(f"❌ No open ports found on {hostname}")
            results[subdomain] = {
                "hostname": hostname,
                "open_ports": [],
                "status": "inactive"
            }
    
    return results