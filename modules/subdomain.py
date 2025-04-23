import subprocess

def find_subdomains(domain):
    """Uses sublist3r to find subdomains of a domain"""
    try:
        print(f"[+] Enumerating subdomains for {domain}...")
        result = subprocess.run(
            ['sublist3r', '-d', domain, '-o', f'{domain}_subdomains.txt'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Check if the process ran successfully
        if result.returncode != 0:
            print(f"[X] Error running sublist3r for {domain}")
            return []

        # Read subdomains from the output file
        with open(f'{domain}_subdomains.txt', 'r') as file:
            subdomains = [line.strip() for line in file.readlines()]
        
        return subdomains
    except Exception as e:
        print(f"[X] Error: {e}")
        return []