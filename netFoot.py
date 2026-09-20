import socket
import whois
import sys
import requests
import ssl
import datetime

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return "unresolved"

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers
        }
    except Exception as e:
        return {"error": str(e)}

def get_ssl_cert(domain):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return {
                "subject": dict(x[0] for x in cert['subject']),
                "issuer": dict(x[0] for x in cert['issuer']),
                "not_after": cert['notAfter']
            }
    except Exception as e:
        return {"error": str(e)}

def check_shodan(ip, api_key):
    if not api_key:
        return {"status": "no api key provided"}
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                "ports": data.get("ports", []),
                "org": data.get("org", "unknown"),
                "country": data.get("country_name", "unknown")
            }
        else:
            return {"error": "api request failed"}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python netFoot.py <domain> [shodan_api_key]")
        sys.exit(1)
    
    domain = sys.argv[1]
    shodan_key = sys.argv[2] if len(sys.argv) > 2 else None
    
    ip = get_ip(domain)
    whois_data = get_whois_info(domain)
    ssl_data = get_ssl_cert(domain)
    shodan_data = check_shodan(ip, shodan_key)
    
    print(f"target: {domain}")
    print(f"ip address: {ip}")
    print("\nwhois information:")
    for key, value in whois_data.items():
        print(f"  {key}: {value}")
    
    print("\nssl certificate:")
    for key, value in ssl_data.items():
        print(f"  {key}: {value}")
        
    print("\nshodan intelligence:")
    for key, value in shodan_data.items():
        print(f"  {key}: {value}")
