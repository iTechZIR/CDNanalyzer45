# ---Creator: t.me/GKSVGK ---Channel: t.me/iTechZIR,t.me/dev_2yt_code_c
#!/usr/bin/env python3

import sys
import socket
import requests
import dns.resolver
import ssl
import json
import os
import random
import re
import threading
from datetime import datetime
import whois
import concurrent.futures
from typing import Dict, List, Any, Optional


class ServerAnalyzer:
    def __init__(self, target: str):
        self.target = target.strip()
        self.is_ip = self._is_ip(self.target)
        self.ip = self.target if self.is_ip else self._resolve_ip(self.target)
        self.results: Dict[str, Any] = {}
        self.session = requests.Session()
        self.session.headers.update(self._random_headers())

    def _random_headers(self) -> Dict[str, str]:
        uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
        ]
        accept_langs = [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "fr-FR,fr;q=0.9,en;q=0.8",
            "de-DE,de;q=0.9,en;q=0.8",
            "es-ES,es;q=0.9,en;q=0.8",
            "it-IT,it;q=0.9,en;q=0.8"
        ]
        accepts = [
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "text/html,application/xml;q=0.9,*/*;q=0.8"
        ]
        return {
            "User-Agent": random.choice(uas),
            "Accept": random.choice(accepts),
            "Accept-Language": random.choice(accept_langs),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1"
        }

    def _is_ip(self, value: str) -> bool:
        try:
            socket.inet_aton(value)
            return True
        except OSError:
            return False

    def _resolve_ip(self, host: str) -> Optional[str]:
        try:
            return socket.gethostbyname(host)
        except Exception:
            return None

    def _get_ip(self) -> Dict[str, Any]:
        if not self.ip:
            return {"error": "Unable to resolve target"}
        try:
            r = self.session.get(f"https://ipinfo.io/{self.ip}/json", timeout=10)
            if r.status_code == 200:
                return r.json()
            return {"error": f"ipinfo status {r.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def _check_cdn(self) -> Dict[str, Any]:
        cdnproviders = {
            "CLOUDFLARE": {
                "names": {"cf-ray", "cf-cache-status", "cf-polished", "cf-bgj", "cf-apo-via"},
                "values": {r"cloudflare"}
            },
            "CLOUDFRONT": {
                "names": {"x-amz-cf-pop", "x-amz-cf-id", "x-cache"},
                "values": {r"cloudfront", r"amazon"}
            },
            "AKAMAI": {
                "names": {"x-akamai-transformed", "akamai-origin-hop", "x-akamai-session-info"},
                "values": {r"akamai"}
            },
            "FASTLY": {
                "names": {"x-served-by", "x-cache-hits", "x-fastly-request-id", "fastly-debug-digest"},
                "values": {r"fastly"}
            },
            "AZURE": {
                "names": {"x-azure-ref", "x-azure-originstatus", "x-msedge-ref"},
                "values": {r"azure", r"microsoft"}
            },
            "GOOGLE": {
                "names": {"x-goog-generation", "x-guploader-uploadid", "x-goog-storage-class", "x-goog-meta"},
                "values": {r"google", r"gws"}
            },
            "IMPERVA": {
                "names": {"x-iinfo", "x-cdn", "incap_ses", "visid_incap"},
                "values": {r"imperva", r"incapsula"}
            },
            "SUCURI": {
                "names": {"x-sucuri-id", "x-sucuri-cache"},
                "values": {r"sucuri"}
            }
        }

        def score_headers(headers: Dict[str, str]) -> Dict[str, Any]:
            scores: Dict[str, int] = {p: 0 for p in cdnproviders}
            indicators: Dict[str, List[str]] = {p: [] for p in cdnproviders}
            lower_map = {k.lower(): v for k, v in headers.items()}

            for provider, sig in cdnproviders.items():
                for hname, hval in lower_map.items():
                    if hname in sig["names"]:
                        scores[provider] += 2
                        indicators[provider].append(f"{hname}: {hval}")
                    for pat in sig["values"]:
                        if re.search(pat, hval, re.I) or re.search(pat, hname, re.I):
                            scores[provider] += 1
                            indicators[provider].append(f"{hname}: {hval}")
            best_provider = max(scores, key=scores.get) if scores else None
            best_score = scores.get(best_provider, 0) if best_provider else 0
            using = best_score > 0
            matched = [p for p, s in scores.items() if s > 0]
            return using, best_provider if using else None, matched, scores, indicators

        urls = []
        if not self.is_ip:
            urls = [f"http://{self.target}", f"https://{self.target}"]
        else:
            urls = [f"http://{self.ip}", f"https://{self.ip}"]

        last_headers: Dict[str, str] = {}
        last_error = None
        for url in urls:
            try:
                r = self.session.get(url, timeout=10, allow_redirects=True, verify=False)
                last_headers = dict(r.headers)
                last_error = None
                break
            except Exception as e:
                last_error = str(e)

        if not last_headers:
            return {
                "using_cdn": False,
                "cdn_provider": None,
                "matched_providers": [],
                "scores": {},
                "cdn_headers": {},
                "cdn_indicators": {},
                "error": last_error
            }

        using, best_provider, matched, scores, indicators = score_headers(last_headers)

        return {
            "using_cdn": using,
            "cdn_provider": best_provider,
            "matched_providers": matched,
            "scores": scores,
            "cdn_headers": last_headers,
            "cdn_indicators": indicators
        }

    def _get_ssl(self) -> Dict[str, Any]:
        sslinfo = {
            "has_ssl": False,
            "issuer": None,
            "expires": None,
            "days_remaining": None,
            "protocol": None,
            "error": None
        }

        host = self.target if not self.is_ip else None
        connect_host = self.target if not self.is_ip else (self.ip or self.target)

        try:
            context = ssl.create_default_context()
            with socket.create_connection((connect_host, 443), timeout=10) as sock:
                if host:
                    ssock = context.wrap_socket(sock, server_hostname=host)
                else:
                    ssock = context.wrap_socket(sock)
                with ssock:
                    cert = ssock.getpeercert()
                    sslinfo["has_ssl"] = True
                    issuer = dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {}
                    sslinfo["issuer"] = issuer.get("organizationName", "Unknown")
                    expiredate = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    sslinfo["expires"] = expiredate.strftime("%Y-%m-%d")
                    sslinfo["days_remaining"] = (expiredate - datetime.now()).days
                    sslinfo["protocol"] = ssock.version()
        except Exception as e:
            sslinfo["error"] = str(e)

        return sslinfo

    def _get_dns(self) -> Dict[str, Any]:
        dnsinfo = {
            "a_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "ptr_records": [],
            "error": None
        }

        if self.is_ip:
            try:
                rev = dns.reversename.from_address(self.ip or self.target)
                answers = dns.resolver.resolve(rev, "PTR")
                dnsinfo["ptr_records"] = [str(r) for r in answers]
            except Exception as e:
                dnsinfo["error"] = str(e)
            return dnsinfo

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            for rtype, key in [("A", "a_records"), ("MX", "mx_records"), ("NS", "ns_records"), ("TXT", "txt_records")]:
                try:
                    answers = resolver.resolve(self.target, rtype)
                    dnsinfo[key] = [str(r) for r in answers]
                except Exception:
                    pass
        except Exception as e:
            dnsinfo["error"] = str(e)

        return dnsinfo

    def _get_whois(self) -> Dict[str, Any]:
        whoisinfo = {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "name_servers": [],
            "status": None,
            "error": None
        }

        if self.is_ip:
            whoisinfo["error"] = "WHOIS is domain-only for this tool"
            return whoisinfo

        try:
            domaininfo = whois.whois(self.target)
            if domaininfo:
                whoisinfo["registrar"] = getattr(domaininfo, "registrar", None)
                whoisinfo["creation_date"] = str(getattr(domaininfo, "creation_date", None))
                whoisinfo["expiration_date"] = str(getattr(domaininfo, "expiration_date", None))
                ns = getattr(domaininfo, "name_servers", None)
                if ns:
                    whoisinfo["name_servers"] = list(ns) if isinstance(ns, (list, tuple, set)) else [ns]
                whoisinfo["status"] = getattr(domaininfo, "status", None)
        except Exception as e:
            whoisinfo["error"] = str(e)

        return whoisinfo

    def _get_servers_headers(self) -> Dict[str, Any]:
        headersinfo: Dict[str, str] = {}
        error = None

        urls = []
        if not self.is_ip:
            urls = [f"https://{self.target}", f"http://{self.target}"]
        else:
            urls = [f"https://{self.ip or self.target}", f"http://{self.ip or self.target}"]

        for url in urls:
            try:
                r = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
                headersinfo = dict(r.headers)
                error = None
                break
            except Exception as e:
                error = str(e)

        return {"headers": headersinfo, "error": error}

    def _get_ports(self) -> List[Dict[str, Any]]:
        commonports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
            587: "SMTP", 993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }

        openports: List[Dict[str, Any]] = []
        lock = threading.Lock()
        connect_host = self.ip or self.target

        def _check_port(port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.2)
                result = sock.connect_ex((connect_host, port))
                sock.close()
                if result == 0:
                    service = commonports.get(port, "Unknown")
                    with lock:
                        openports.append({"port": port, "service": service, "status": "OPEN"})
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            list(executor.map(_check_port, commonports.keys()))

        return sorted(openports, key=lambda x: x["port"])

    def analyze(self) -> Dict[str, Any]:
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = {
                "ip_info": executor.submit(self._get_ip),
                "cdn_info": executor.submit(self._check_cdn),
                "ssl_info": executor.submit(self._get_ssl),
                "dns_info": executor.submit(self._get_dns),
                "whois_info": executor.submit(self._get_whois),
                "ports_info": executor.submit(self._get_ports),
                "headers_info": executor.submit(self._get_servers_headers)
            }
            for key, future in futures.items():
                try:
                    self.results[key] = future.result()
                except Exception as e:
                    self.results[key] = {"error": str(e)}
        return self.results


def _save_logging(target: str, results: Dict[str, Any]):
    logdata = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "results": results
    }
    try:
        with open("__logging__.json", "w", encoding="utf-8") as f:
            json.dump(logdata, f, indent=2, ensure_ascii=False, default=str)
        print("[+] - save log")
        choice = input("[+] - do you want to open the json file ? (y/n): ").strip().lower()
        if choice == "y":
            try:
                filepath = os.path.abspath("__logging__.json")
                if os.name == "nt":
                    os.system(f'start "" "{filepath}"')
                elif os.name == "posix":
                    if sys.platform == "darwin":
                        os.system(f'open "{filepath}"')
                    else:
                        os.system(f'xdg-open "{filepath}"')
            except Exception:
                pass
    except Exception:
        pass


def main():
    print("""
╔══════════════════════════════════════════════════════╗
║                   CDNanalyzer45                      ║
║             Server & CDN Analyzer Tool               ║
║                                                      ║
║            Version: 1.1    Creator: 2yt              ║
╚══════════════════════════════════════════════════════╝
""")

    target = input("\n - please enter the ip or domain: ").strip()
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
