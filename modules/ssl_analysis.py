# SSL/TLS analysis using sslyze
import socket
import ssl
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def get_ssl_info(hostname, port=443, timeout=5):
    """Get SSL/TLS certificate information for a host"""
    context = ssl.create_default_context()
    context.set_ciphers('ALL:@SECLEVEL=1')
    
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                # Get certificate validity dates
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                
                # Check certificate expiration
                days_remaining = (not_after - datetime.now()).days
                
                # Get supported protocols
                protocols = []
                for proto in ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']:
                    try:
                        proto_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                        proto_context.set_ciphers('DEFAULT')
                        proto_context.minimum_version = getattr(ssl, f"PROTOCOL_{proto}")
                        proto_context.verify_mode = ssl.CERT_REQUIRED
                        
                        with socket.create_connection((hostname, port), timeout=timeout) as proto_sock:
                            with proto_context.wrap_socket(proto_sock, server_hostname=hostname):
                                protocols.append(proto)
                    except:
                        pass
                
                return {
                    'hostname': hostname,
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'subject': dict(x[0] for x in cert['subject']),
                    'valid_from': not_before.isoformat(),
                    'valid_to': not_after.isoformat(),
                    'days_remaining': days_remaining,
                    'serial_number': cert.get('serialNumber', ''),
                    'signature_algorithm': cert.get('signatureAlgorithm', ''),
                    'version': cert.get('version', ''),
                    'cipher': {
                        'name': cipher[0],
                        'protocol': cipher[1],
                        'bits': cipher[2]
                    },
                    'protocols_supported': protocols,
                    'is_valid': days_remaining > 0,
                    'is_weak': any(proto in protocols for proto in ['TLSv1', 'TLSv1.1']),
                    'status': 'success'
                }
    
    except Exception as e:
        return {
            'hostname': hostname,
            'status': 'error',
            'error': str(e)
        }

def analyze_ssl(subdomains):
    """Analyze SSL/TLS for multiple subdomains"""
    results = {}
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_host = {
            executor.submit(get_ssl_info, 
                          subdomain.split('//')[1].split('/')[0] if subdomain.startswith(('http://', 'https://')) else subdomain.split('/')[0]): 
            subdomain for subdomain in subdomains
        }
        
        for future in future_to_host:
            subdomain = future_to_host[future]
            try:
                result = future.result()
                results[subdomain] = result
                
                if result['status'] == 'success':
                    print(f"🔒 SSL analysis for {subdomain}: Valid until {result['valid_to']} ({result['days_remaining']} days remaining)")
                    if result['is_weak']:
                        print(f"⚠️  Warning: Weak protocols detected ({', '.join(proto for proto in result['protocols_supported'] if proto in ['TLSv1', 'TLSv1.1'])})")
                else:
                    print(f"❌ SSL analysis failed for {subdomain}: {result['error']}")
                    
            except Exception as e:
                results[subdomain] = {
                    'hostname': subdomain,
                    'status': 'error',
                    'error': str(e)
                }
                print(f"❌ Error analyzing {subdomain}: {e}")
    
    return results