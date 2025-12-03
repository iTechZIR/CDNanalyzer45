# ---Creator: t.me/GKSVGK ---Channel: t.me/iTechZIR,t.me/dev_2yt_code_c
#!/usr/bin/env python3

import sys
import socket
import requests
import dns.resolver
import ssl
import json
import os
from datetime import datetime
import whois
import concurrent.futures
from typing import Dict, List, Any

class ServerAnalyzer:
    def __init__(self, target: str):
        self.target = target.strip()
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def _get_ip(self) -> Dict[str, Any]:
        try:
            try:
                socket.inet_aton(self.target)
                ip = self.target
            except socket.error:
                ip = socket.gethostbyname(self.target)

            response = self.session.get(f'https://ipinfo.io/{ip}/json', timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return {}

    def _check_cdn(self) -> Dict[str, Any]:
        cdninfo = {
            'using_cdn': False,
            'cdn_provider': None,
            'cdn_headers': {},
            'cdn_indicators': []
        }
        cdnproviders = {
            'cloudflare': ['cf-ray', 'cf-cache-status', 'server', 'cf-polished'],
            'cloudfront': ['x-amz-cf-pop', 'x-amz-cf-id', 'x-cache'],
            'akamai': ['x-akamai-transformed', 'akamai-origin-hop'],
            'fastly': ['x-served-by', 'x-cache-hits', 'x-fastly-request-id'],
            'azure': ['x-azure-ref', 'x-azure-originstatus'],
            'google': ['x-goog-generation', 'x-guploader-uploadid'],
            'imperva': ['incap_ses_', 'visid_incap_'],
            'sucuri': ['x-sucuri-id', 'x-sucuri-cache']
        }
        try:
            response = self.session.get(f'http://{self.target}', timeout=10, allow_redirects=True)
            headers = dict(response.headers)
            for provider, indicators in cdnproviders.items():
                for indicator in indicators:
                    for header in headers:
                        if indicator.lower() in header.lower():
                            cdninfo['using_cdn'] = True
                            cdninfo['cdn_provider'] = provider.upper()
                            cdninfo['cdn_indicators'].append(f"{header}: {headers[header]}")
            cdninfo['cdn_headers'] = headers
        except:
            try:
                response = self.session.get(f'https://{self.target}', timeout=10, verify=True)
                headers = dict(response.headers)
                for provider, indicators in cdnproviders.items():
                    for indicator in indicators:
                        for header in headers:
                            if indicator.lower() in header.lower():
                                cdninfo['using_cdn'] = True
                                cdninfo['cdn_provider'] = provider.upper()
                                cdninfo['cdn_indicators'].append(f"{header}: {headers[header]}")
                cdninfo['cdn_headers'] = headers
            except:
                pass
        return cdninfo

    def _get_ssl(self) -> Dict[str, Any]:
        sslinfo = {
            'has_ssl': False,
            'issuer': None,
            'expires': None,
            'days_remaining': None,
            'protocol': None
        }
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    sslinfo['has_ssl'] = True
                    issuer = dict(x[0] for x in cert['issuer'])
                    sslinfo['issuer'] = issuer.get('organizationName', 'Unknown')
                    expiredate = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    sslinfo['expires'] = expiredate.strftime('%Y-%m-%d')
                    daysremaining = (expiredate - datetime.now()).days
                    sslinfo['days_remaining'] = daysremaining
                    sslinfo['protocol'] = ssock.version()
        except:
            pass
        return sslinfo

    def _get_dns(self) -> Dict[str, Any]:
        dnsinfo = {
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': []
        }
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            try:
                answers = resolver.resolve(self.target, 'A')
                dnsinfo['a_records'] = [str(r) for r in answers]
            except:
                pass
            try:
                answers = resolver.resolve(self.target, 'MX')
                dnsinfo['mx_records'] = [str(r) for r in answers]
            except:
                pass
            try:
                answers = resolver.resolve(self.target, 'NS')
                dnsinfo['ns_records'] = [str(r) for r in answers]
            except:
                pass
            try:
                answers = resolver.resolve(self.target, 'TXT')
                dnsinfo['txt_records'] = [str(r) for r in answers]
            except:
                pass
        except:
            pass
        return dnsinfo

    def _get_whois(self) -> Dict[str, Any]:
        whoisinfo = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'name_servers': [],
            'status': None
        }
        try:
            domaininfo = whois.whois(self.target)
            if domaininfo:
                whoisinfo['registrar'] = domaininfo.registrar
                whoisinfo['creation_date'] = str(domaininfo.creation_date)
                whoisinfo['expiration_date'] = str(domaininfo.expiration_date)
                if domaininfo.name_servers:
                    whoisinfo['name_servers'] = list(domaininfo.name_servers) if isinstance(domaininfo.name_servers, list) else [domaininfo.name_servers]
                whoisinfo['status'] = domaininfo.status
        except:
            pass
        return whoisinfo

    def _get_servers_headers(self) -> Dict[str, str]:
        headersinfo = {}
        try:
            response = self.session.get(f'https://{self.target}', timeout=10, verify=False)
            headersinfo = dict(response.headers)
        except:
            try:
                response = self.session.get(f'http://{self.target}', timeout=10)
                headersinfo = dict(response.headers)
            except:
                pass
        return headersinfo

    def _get_ports(self) -> List[Dict[str, Any]]:
        commonports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS',
            587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        openports = []
        def _check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                sock.close()
                if result == 0:
                    service = commonports.get(port, 'Unknown')
                    openports.append({'port': port, 'service': service, 'status': 'OPEN'})
            except:
                pass
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(_check_port, commonports.keys())
        return sorted(openports, key=lambda x: x['port'])

    def analyze(self) -> Dict[str, Any]:
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = {
                'ip_info': executor.submit(self._get_ip),
                'cdn_info': executor.submit(self._check_cdn),
                'ssl_info': executor.submit(self._get_ssl),
                'dns_info': executor.submit(self._get_dns),
                'whois_info': executor.submit(self._get_whois),
                'ports_info': executor.submit(self._get_ports),
                'headers_info': executor.submit(self._get_servers_headers)
            }
            for key, future in futures.items():
                self.results[key] = future.result()
        return self.results

def _save_logging(target: str, results: Dict[str, Any]):
    logdata = {
        'timestamp': datetime.now().isoformat(),
        'target': target,
        'results': results
    }
    try:
        with open('__logging__.json', 'w') as f:
            json.dump(logdata, f, indent=2, ensure_ascii=False, default=str)
        print("[+] - save log")
        choice = input("[+] - do you want to open the json file ? (y/n): ").strip().lower()
        if choice == 'y':
            try:
                filepath = os.path.abspath('__logging__.json')
                if os.name == 'nt': 
                    os.system(f'start "" "{filepath}"')
                elif os.name == 'posix':  
                    if sys.platform == 'darwin':  
                        os.system(f'open "{filepath}"')
                    else:  
                        os.system(f'xdg-open "{filepath}"')
            except:
                pass
    except Exception as e:
        pass

def main():
    print("""
╔══════════════════════════════════════════════════════╗
║                   CDNanalyzer45                      ║
║             Server & CDN Analyzer Tool               ║
║                                                      ║
║            Version: 1.0    Creator: 2yt              ║
╚══════════════════════════════════════════════════════╝
""")
    
    target = input("\n - please enter the ip: ").strip()
    
    if not target:
        sys.exit(1)
    
    analyzer = ServerAnalyzer(target)
    results = analyzer.analyze()
    _save_logging(target, results)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception:
        pass