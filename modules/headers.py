import os
import httpx
import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from datetime import datetime

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Content-Security-Policy',
    'Referrer-Policy',
    'Permissions-Policy'
]

def check_security_headers(url):
    """Check security headers for a single URL"""
    result = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'status': 'success',
        'security_score': 0,
        'total_headers_checked': len(SECURITY_HEADERS)
    }
    
    headers = {header: 'missing' for header in SECURITY_HEADERS}
    
    try:
        # Ensure we're testing HTTPS
        if not url.startswith('http'):
            url = f'https://{url}'
        elif url.startswith('http://'):
            url = url.replace('http://', 'https://')
        
        # Extract domain for Host header
        domain = urlparse(url).netloc
        
        # Create client with SSL verification enabled
        client = httpx.Client(
            timeout=10,
            follow_redirects=True,
            verify=True  # SSL verification happens here at client level
        )
        
        with client:
            response = client.get(
                url,
                headers={'Host': domain}
            )
            
            # Check each security header
            present_headers = 0
            for header in SECURITY_HEADERS:
                if header in response.headers:
                    headers[header] = 'present'
                    present_headers += 1
                    # Store header value if present
                    headers[f'{header}_value'] = response.headers[header]
                else:
                    headers[header] = 'missing'
            
            result['security_score'] = f"{present_headers}/{len(SECURITY_HEADERS)}"
            result['headers'] = headers
            result['status_code'] = response.status_code
    
    except httpx.ConnectError:
        result['status'] = 'connection_error'
    except httpx.TimeoutException:
        result['status'] = 'timeout'
    except httpx.HTTPError as e:
        result['status'] = f'http_error ({str(e)})'
    except Exception as e:
        result['status'] = f'error ({str(e)})'
    
    return result

# ... (rest of the functions remain the same)

def analyze_headers(subdomains):
    """Analyze security headers for multiple subdomains"""
    results = {}
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {
            executor.submit(check_security_headers, 
                          subdomain.split('//')[1].split('/')[0] if subdomain.startswith(('http://', 'https://')) else subdomain.split('/')[0]): 
            subdomain for subdomain in subdomains
        }
        
        for future in future_to_url:
            subdomain = future_to_url[future]
            try:
                result = future.result()
                results[subdomain] = result
                
                if result['status'] == 'success':
                    print(f"🔍 {subdomain}: Score {result['security_score']}")
                    if 'missing' in [result['headers'][h] for h in SECURITY_HEADERS]:
                        missing = [h for h in SECURITY_HEADERS if result['headers'][h] == 'missing']
                        print(f"⚠️  Missing headers: {', '.join(missing)}")
                else:
                    print(f"❌ {subdomain}: {result['status']}")
                    
            except Exception as e:
                results[subdomain] = {
                    'url': subdomain,
                    'status': f'processing_error ({str(e)})',
                    'timestamp': datetime.now().isoformat()
                }
                print(f"❌ Error analyzing {subdomain}: {e}")
    
    return results

def save_header_results(domain, data):
    """Save header analysis results to JSON file"""
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, f"{domain}_headers.json")
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"[+] Header analysis results saved to {filepath}")

def print_summary(results):
    """Print summary of header analysis"""
    successful_scans = [r for r in results.values() if r['status'] == 'success']
    
    if not successful_scans:
        print("\n❌ No successful scans to analyze")
        return
    
    print("\n📊 Security Header Analysis Summary:")
    print(f"Total subdomains scanned: {len(results)}")
    print(f"Successfully analyzed: {len(successful_scans)}")
    print(f"Failed scans: {len(results) - len(successful_scans)}")
    
    # Calculate average security score
    total_score = sum(int(s['security_score'].split('/')[0]) for s in successful_scans)
    max_possible = len(SECURITY_HEADERS) * len(successful_scans)
    avg_score = (total_score / max_possible) * 100 if max_possible > 0 else 0
    
    print(f"\n🔒 Average security score: {avg_score:.1f}%")
    
    # Print header presence statistics
    print("\n📌 Header Presence Statistics:")
    for header in SECURITY_HEADERS:
        present_count = sum(1 for r in successful_scans if r['headers'][header] == 'present')
        percentage = (present_count / len(successful_scans)) * 100 if successful_scans else 0
        print(f"{header}: {present_count}/{len(successful_scans)} ({percentage:.1f}%)")
    
    # Identify most common missing headers
    missing_counts = {header: 0 for header in SECURITY_HEADERS}
    for scan in successful_scans:
        for header in SECURITY_HEADERS:
            if scan['headers'][header] == 'missing':
                missing_counts[header] += 1
    
    print("\n⚠️  Most Commonly Missing Headers:")
    for header, count in sorted(missing_counts.items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            print(f"{header}: {count} subdomains")