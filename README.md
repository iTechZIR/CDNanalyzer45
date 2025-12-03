> # CDNanalyzer45 - Server & CDN Analysis Tool

A comprehensive Python-based tool for server analysis, CDN detection, and network diagnostics with multi-source intelligence gathering.

> ## Overview

CDNanalyzer45 is an advanced server analysis tool designed for security professionals, network administrators, and developers. It provides detailed insights into server configurations, CDN usage, SSL certificates, and network infrastructure through automated multi-threaded analysis.

> ## Features

- **CDN Detection**: Automatic identification of major CDN providers including Cloudflare, CloudFront, Akamai, Fastly, and Azure
- **SSL Certificate Analysis**: Comprehensive SSL/TLS inspection including issuer, expiration, and protocol details
- **Network Intelligence**: IP geolocation, DNS records, WHOIS information, and port scanning
- **Multi-threaded Analysis**: Parallel processing for faster results
- **Log Management**: Automated JSON logging with user-friendly file access
- **Cross-platform Compatibility**: Full support for Windows, Linux, and macOS
- **Minimalist Interface**: Clean, focused output with essential information only

> ## Installation

> ### Requirements
- Python 3.6 or higher
- Required Python libraries

> ### Setup
```bash
# Install required packages
pip install requests dnspython whois
```

> ## Project Structure

```
cdnanalyzer45/
├── cdn_analyzer.py                 # Main analyzer script
├── __logging__.json     # Automated analysis logs
└── README.md                       # Documentation
```

> ## Usage

> ### Basic Command

```bash
# Launch the analyzer
python cdn_analyzer.py
```

> ### Interactive Flow
1. Run the script
2. Enter target IP address or domain when prompted
3. Wait for analysis to complete
5. Save log to `__logging__.json`
6. Choose to open JSON file for detailed results

> ### Command Examples

```bash
# Analyze any server
python cdn_analyzer.py
```

> ## Data Collection

> ### Information Gathered

**IP Intelligence:**
- IP address and hostname
- Geographic location (city, region, country)
- Internet Service Provider (ISP)
- Network organization

**CDN Detection:**
- CDN provider identification
- CDN-specific header analysis
- Cloud service detection (Cloudflare, AWS, Azure, Google)

**SSL Certificate Analysis:**
- Certificate validity status
- Issuing authority
- Expiration date and remaining days
- SSL/TLS protocol version

**DNS Records:**
- A records (IPv4 addresses)
- MX records (mail servers)
- NS records (name servers)
- TXT records (text records)

**Network Ports:**
- Common port scanning (21, 22, 80, 443, 8080, etc.)
- Service identification
- Port status (open/closed)

**WHOIS Information:**
- Domain registrar
- Creation and expiration dates
- Name servers
- Domain status

> ## Supported CDN Providers

- ✅ **Cloudflare**: Detected via cf-ray, cf-cache-status headers
- ✅ **Amazon CloudFront**: Detected via x-amz-cf-pop, x-amz-cf-id headers
- ✅ **Akamai**: Detected via x-akamai-transformed headers
- ✅ **Fastly**: Detected via x-served-by, x-fastly-request-id headers
- ✅ **Microsoft Azure**: Detected via x-azure-ref headers
- ✅ **Google Cloud**: Detected via x-goog-generation headers
- ✅ **Imperva**: Detected via incap_ses_, visid_incap_ headers
- ✅ **Sucuri**: Detected via x-sucuri-id headers

> ## Port Scanning Coverage

The tool scans common ports for service discovery:

**Web Services:**
- 80 (HTTP)
- 443 (HTTPS)
- 8080 (HTTP-Alt)
- 8443 (HTTPS-Alt)

**Email Services:**
- 25 (SMTP)
- 110 (POP3)
- 143 (IMAP)
- 465 (SMTPS)
- 993 (IMAPS)
- 995 (POP3S)

**Remote Access:**
- 21 (FTP)
- 22 (SSH)
- 23 (Telnet)
- 3389 (RDP)

**Database Services:**
- 3306 (MySQL)
- 5432 (PostgreSQL)

**DNS Service:**
- 53 (DNS)

> ## Log Format

Analysis results are saved in `__logging__.json` with the following structure:

```json
{
  "timestamp": "2024-01-15T14:30:22.123456",
  "target": "example.com",
  "results": {
    "ip_info": {
      "ip": "93.184.216.34",
      "hostname": "example.com",
      "city": "Los Angeles",
      "region": "California",
      "country": "US",
      "org": "CDN-By-Cloudflare"
    },
    "cdn_info": {
      "using_cdn": true,
      "cdn_provider": "CLOUDFLARE",
      "cdn_headers": {},
      "cdn_indicators": []
    },
    "ssl_info": {
      "has_ssl": true,
      "issuer": "Cloudflare Inc",
      "expires": "2024-12-31",
      "days_remaining": 180,
      "protocol": "TLSv1.3"
    },
    "dns_info": {
      "a_records": ["93.184.216.34"],
      "mx_records": [],
      "ns_records": ["a.iana-servers.net"],
      "txt_records": []
    },
    "whois_info": {
      "registrar": "Example Registrar",
      "creation_date": "1995-08-15",
      "expiration_date": "2025-08-14",
      "name_servers": ["ns1.example.com"],
      "status": "active"
    },
    "ports_info": [
      {"port": 80, "service": "HTTP", "status": "OPEN"},
      {"port": 443, "service": "HTTPS", "status": "OPEN"}
    ],
    "headers_info": {
      "server": "cloudflare",
      "content-type": "text/html"
    }
  }
}
```

> ## Performance Optimization

- **Parallel Processing**: Uses concurrent.futures for simultaneous checks
- **Connection Pooling**: Reusable HTTP sessions for faster requests
- **Timeout Management**: Configurable timeouts for network operations
- **Error Resilience**: Graceful error handling without process interruption

> ## Error Handling

The tool includes robust error handling for:
- Network connectivity issues
- DNS resolution failures
- SSL certificate errors
- Port connection timeouts
- API rate limiting
- Invalid target formats

> ## Examples

### Example 1: Basic Server Analysis
```bash
python cdn_analyzer.py
# Enter: google.com
```

> ### Example 2: CDN Detection
```bash
python cdn_analyzer.py
# Enter: cloudflare.com
# Log shows: "cdn_provider": "CLOUDFLARE"
```

> ### Example 3: SSL Inspection
```bash
python cdn_analyzer.py
# Enter: github.com
# Log shows SSL certificate details including issuer and expiration
```

> ## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -m 'Add some improvement'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

> ## License

This project is licensed under the MIT License - see the LICENSE file for details.

> ## Support

For support, questions, or feature requests:
- Open an issue in the GitHub repository
- Check the documentation for troubleshooting
- Review existing issues for similar problems

> ## Version History

1.0.0 - Initial release
- CDN detection for major providers
- SSL certificate analysis
- Port scanning capabilities
- IP intelligence gathering
- Automated JSON logging
- Cross-platform compatibility

> ## Author

**Creator**: 2yt
**Telegram**: [@GKSVGK](https://t.me/GKSVGK)
**Channels**: [@iTechZIR](https://t.me/iTechZIR), [@dev_2yt_code_c](https://t.me/dev_2yt_code_c)

> ## Acknowledgments

- Thanks to ipinfo.io for IP intelligence API
- Python community for excellent networking libraries
- Contributors and testers for feedback and improvements

---

⭐ If you find this tool useful, please give it a star on GitHub !
