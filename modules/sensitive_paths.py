# Hidden/sensitive file discovery
import os
import httpx
import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from datetime import datetime

SENSITIVE_PATHS = [
    '/admin',
    '/login',
    '/.git',
    '/.env',
    '/config.php',
    '/.DS_Store',
    '/backend',
    '/debug',
    '/test',
    '/server-status'
]

SENSITIVE_STATUS_CODES = {200, 401, 403}

def test_sensitive_path(subdomain, path):
    """Test a single sensitive path on a subdomain"""
    url = urljoin(f"https://{subdomain}", path)
    result = {
        'path': path,
        'url': url,
        'status': 'pending',
        'timestamp': datetime.now().isoformat()
    }
    
    try:
        with httpx.Client(timeout=10, follow_redirects=False) as client:
            response = client.get(url)
            
            if response.status_code in SENSITIVE_STATUS_CODES:
                result.update({
                    'status': 'sensitive',
                    'status_code': response.status_code,
                    'reason': response.reason_phrase,
                    'content_type': response.headers.get('content-type', ''),
                    'content_length': len(response.content)
                })
            else:
                result.update({
                    'status': 'safe',
                    'status_code': response.status_code,
                    'reason': response.reason_phrase
                })
    
    except httpx.ConnectError:
        result['status'] = 'connection_error'
    except httpx.TimeoutException:
        result['status'] = 'timeout'
    except httpx.HTTPError as e:
        result['status'] = f'http_error ({str(e)})'
    except Exception as e:
        result['status'] = f'error ({str(e)})'
    
    return result

def scan_sensitive_paths(subdomains):
    """Scan sensitive paths on multiple subdomains"""
    results = {}
    total_tested = 0
    sensitive_found = 0
    failed_requests = 0
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        # Create all tasks
        futures = []
        for subdomain in subdomains:
            results[subdomain] = {}
            for path in SENSITIVE_PATHS:
                futures.append(executor.submit(test_sensitive_path, subdomain, path))
                total_tested += 1
        
        # Process results as they complete
        for future in futures:
            try:
                result = future.result()
                subdomain = result['url'].split('/')[2]  # Extract domain from URL
                
                if result['status'] == 'sensitive':
                    sensitive_found += 1
                    results[subdomain][result['path']] = {
                        'status': result['status_code'],
                        'reason': result['reason'],
                        'content_type': result.get('content_type', ''),
                        'content_length': result.get('content_length', 0)
                    }
                    print(f"⚠️  Sensitive path found: {result['url']} ({result['status_code']})")
                elif result['status'] in ['connection_error', 'timeout', 'http_error']:
                    failed_requests += 1
                
            except Exception as e:
                failed_requests += 1
                print(f"❌ Error processing request: {str(e)}")
    
    return {
        'results': results,
        'summary': {
            'total_tested': total_tested,
            'sensitive_found': sensitive_found,
            'failed_requests': failed_requests,
            'scan_time': datetime.now().isoformat()
        }
    }

def save_sensitive_paths_results(domain, data):
    """Save sensitive paths results to JSON file"""
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, f"{domain}_sensitive_paths.json")
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"[+] Sensitive paths results saved to {filepath}")

def print_sensitive_paths_summary(data):
    """Print summary of sensitive paths scan"""
    summary = data['summary']
    
    print("\n📊 Sensitive Paths Scan Summary:")
    print(f"Total URLs tested: {summary['total_tested']}")
    print(f"Sensitive paths found: {summary['sensitive_found']}")
    print(f"Failed requests: {summary['failed_requests']}")
    
    if summary['sensitive_found'] > 0:
        print("\n⚠️  Sensitive Paths Found:")
        for subdomain, paths in data['results'].items():
            if paths:
                print(f"\n🌐 {subdomain}:")
                for path, info in paths.items():
                    print(f"  {path}: {info['status']} ({info['reason']})")