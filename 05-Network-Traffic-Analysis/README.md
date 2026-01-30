# Network Traffic Analysis - DNS & HTTP Investigation

##  Objective
Capture and analyze network traffic from a Windows VM to identify potential DNS and HTTP anomalies that could indicate malicious activity such as data exfiltration, C2 communication, or credential theft.

## Tools Used
- *Wireshark 4.x* - Network protocol analyzer on Kali
- *VirtualBox* - Running Kali Linux VM
- *VMware* - Running Metasploitable3 VM (Sniffed Machine)
- *IP Address* - 172.20.10.3

## 📊 Traffic Capture Summary

![Wireshark Capture Overview](screenshots/01-wireshark-capture-overview.png)
Initial packet capture showing 1405 total packets captured during browsing session

- *Capture Duration*: 2 minutes 56 seconds
- *Total Packets*: 1405 packets
- *Protocols*: DNS, HTTP, TCP, UDP, SSDP
- *Source IP*: 172.20.10.3 (Windows VM)
- *Gateway*: 172.20.10.1

---

## Part 1: DNS Traffic Analysis

### Objective
Identify indicators of compromise in DNS traffic:
- DNS tunneling (excessively long domains)
- Domain Generation Algorithms (random-looking domains)
- High query frequency (beaconing)
- Suspicious top-level domains

### Analysis Process

#### Step 1: Isolate DNS Traffic

![DNS Filter Applied](screenshots/02-dns-filter-basic.png)
Applied filter: dns - Showing only DNS packets

*Filter Used:* dns
*Results*: 71 DNS packets identified

#### Step 2: Statistical Overview

![DNS Statistics](screenshots/03-dns-statistics.png)
Statistics → DNS showing all queried domains with frequency counts

*Domains Observed*:
- facebook.com
- google.com
- www.linkedin.com
  
#### Step 3: Check for Excessively Long Domain Names (DNS Tunneling)

![Long Domain Check](screenshots/04-dns-long-domain-check.png)
Filter: dns.qry.name.len > 50 - Testing for DNS tunneling attempts

*Filters Tested:* 
- dns.qry.name.len > 50
- dns.qry.name > 70
- dns.qry.name > 100
  
*Finding: ✅ **No domains exceeding length thresholds*
- Result: No DNS tunneling detected
- Longest domain: 26 characters

#### Step 4: Identify Failed DNS Queries (Potential DGA)

![NXDOMAIN Responses](screenshots/05-dns-nxdomain-responses.png)
Filter: dns.flags.rcode == 3 - Showing non-existent domain responses

*Filter Used:* dns.flags.rcode == 3

*Findings*: 
- *2 NXDOMAIN responses detected*
- *Source IP*: 172.20.10.1 (Gateway/Router)
- *Query Type*: PTR (Reverse DNS lookups)
- *Domains*: 2 .in-addr.arpa format

*Analysis*: 
These are *benign* - PTR queries are reverse DNS lookups performed by the router for logging purposes. The source is the gateway, not the VM, and failed PTR lookups are common for IPs without reverse DNS records configured.

#### Step 5: Domain Name Inspection

![DNS Query Names](screenshots/06-dns-with-query-column.png)
Added dns.qry.name as column for visual inspection of all queried domains

*Manual Review*: Inspected all domain names for:
- ❌ Random character sequences
- ❌ High consonant-to-vowel ratios
- ❌ Algorithmically-generated patterns
- ❌ Suspicious TLDs (.xyz, .top, .tk, .ml, .ga)

 *Results*: ✅ All domains appear legitimate

### DNS Analysis Summary

| Check | Filter/Method | Result | Indicator |
|-------|--------------|--------|-----------|
| Long domains (>50 chars) | dns.qry.name.len > 50 | None found | ✅ Clean |
| Long domains (>100 chars) | dns.qry.name.len > 100 | None found | ✅ Clean |
| NXDOMAIN responses | dns.flags.rcode == 3 | 2 found (PTR from router) | ✅ Benign |
| Suspicious TLDs | Manual review | None detected | ✅ Clean |
| DGA patterns | Visual inspection | No random strings | ✅ Clean |
| Query frequency | Statistics view | Normal distribution | ✅ Clean |

*Conclusion*: No malicious DNS activity detected. All DNS queries appear to be legitimate browsing traffic.

---

## Part 2: HTTP Traffic Analysis

### Objective
Identify security issues in HTTP traffic:
- Connections to IP addresses (bypassing DNS)
- Suspicious User-Agent strings (malware indicators)
- Repeated outbound requests (C2 beaconing)
- Cleartext credentials in POST data

### Analysis Process

#### Step 1: Isolate HTTP Traffic

![HTTP Filter Applied](screenshots/07-http-filter-basic.png)
Applied filter: http - Displaying only HTTP protocol packets

*Filter Used: http

#### Step 2: Analyze HTTP Requests by Host

![HTTP Statistics](screenshots/08-http-statistics-requests.png)
Statistics → HTTP → Requests - Overview of all HTTP destinations

*Key Finding: **HTTP Request to IP Address Detected*

*Hosts Contacted*:
1. *www.bing.com* - 6 requests
2. *example.com* - 2 requests  
3. *239.255.255.250:1900* - ⚠️ *Direct IP address connection*

#### Step 3: Investigate IP Address Connection

![IP Address Connection Detail](screenshots/09-http-ip-address-detail.png)
Detailed view of HTTP traffic to 239.255.255.250 - SSDP multicast traffic

*Filter Used:* ip.dst == 239.255.255.250

*Analysis of 239.255.255.250:1900*:
- *IP Type*: Multicast address (239.x.x.x range)
- *Port*: 1900 (SSDP - Simple Service Discovery Protocol)
- *Protocol*: UPnP (Universal Plug and Play)
- *Purpose*: Windows device discovery for network devices (printers, media servers, smart devices)
- *Method*: M-SEARCH (discovery request)

*Assessment: ✅ **BENIGN* - This is standard Windows networking behavior, not malicious C2 communication.

#### Step 4: User-Agent Analysis

![User-Agent String](screenshots/10-http-user-agent.png)
Examining User-Agent header from HTTP request packet details

*User-Agent Observed*: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET4.OC; .NET4.0E) 

*Analysis*:
- Matches legitimate browser: Mozilla/4.0
- No suspicious indicators (e.g., python-requests, curl, outdated IE)
- Consistent with Windows VM environment

*Result*: ✅ Normal browser identification

#### Step 5: Review HTTP Request Details

![HTTP Request Columns](screenshots/11-http-with-columns.png)
HTTP traffic with host, method, and URI columns for comprehensive view

*Columns Added*: 
- http.host - Destination hostname
- http.request.method - HTTP method (GET/POST)
- http.request.uri - Requested path

*Observed Requests to www.bing.com*:
GET /search?q=neverssl.com&src=IE-SearchBox&FORM=IE8SRC
GET /rp/OnGp9kULDjUxGHteCtbTCehHngI.gz.js
GET /rp/SrqGloMo94v3vwNVR5OsxDNd8d0.svg
GET /rp/3YUbGQ75v1RodneurDqn2YE2SLl.png
GET /fd/ls/l?IG=…&Type=Event.CPT&DATA=…
GET /favicon.ico

*Analysis*: All requests are legitimate web resources (search, JavaScript, images, analytics, favicon)

#### Step 6: Check for POST Requests (Credential Exposure)

![POST Request Check](screenshots/12-http-post-check.png)
*Filter: http.request.method == "POST" - Checking for form submissions*

*Filter Used:* http.request.method == "POST"
*Results*: Displayed: 0

*If POST requests found*: 
- Click packet → Right-click → Follow → HTTP Stream
- Inspect form data for credentials
- Look for: username=, password=, login=, api_key=

*Result*: No POST requests

### HTTP Analysis Summary

| Check | Filter/Method | Finding | Assessment |
|-------|---------------|---------|------------|
| IP address connections | Statistics → HTTP → Requests | 239.255.255.250:1900 | ✅ SSDP (benign) |
| Suspicious domains | Manual review | www.bing.com, example.com | ✅ Legitimate |
| User-Agent | Packet inspection | Mozilla/4.0 | ✅ Normal |
| POST requests | http.request.method == "POST" | None | ✅ Safe |
| Request frequency | Statistics view | Normal distribution | ✅ No beaconing |
| File downloads | File → Export Objects → HTTP | Standard web resources | ✅ Clean |

*Conclusion*: No indicators of compromise in HTTP traffic. All activity consistent with normal web browsing.

---

## 🎓 Key Learnings

### 1. *Context is Critical*
- Not all IP address connections are malicious
- SSDP (239.255.255.250:1900) is legitimate Windows networking
- Source IP matters: Router vs VM vs External

### 2. *Understanding Normal Behavior*
- *PTR queries* (reverse DNS) from routers are expected
- *NXDOMAIN* responses don't always indicate DGA malware
- *UPnP/SSDP* multicast is standard for device discovery
- Failed DNS lookups can have benign causes

### 3. *Wireshark Proficiency*
- Display filters enable targeted analysis
- Statistics views provide aggregate insights quickly
- Column customization improves workflow
- Follow Stream useful for deep inspection

### 4. *False Positive Reduction*
- Protocol knowledge prevents misidentification
- Infrastructure traffic (router, gateway) should be distinguished
- Baseline normal activity before hunting anomalies

---

##  Indicators of Compromise Reference

### DNS Red Flags (Not Found in This Capture)
- [ ] Domain names >100 characters (DNS tunneling)
- [ ] High-entropy random strings (xkq7mpz.xyz)
- [ ] 50+ NXDOMAIN from same source in <5 minutes
- [ ] Queries to known malicious TLDs without legitimate context
- [ ] Beaconing pattern (regular intervals, e.g., every 60s)
- [ ] Excessive TXT record queries to random domains
- [ ] Base64-like strings in subdomains

### HTTP Red Flags (Not Found in This Capture)
- [ ] Connections to unknown public IP addresses
- [ ] Suspicious User-Agents:
  - Command-line tools (curl, wget, python-requests)
  - Very outdated browsers (IE 6, 7)
  - Misspelled or custom agents
  - Empty User-Agent headers
- [ ] POST to unknown servers with form data
- [ ] Basic Authentication headers (easily decoded)
- [ ] Credentials in URL parameters (?user=admin&pass=123)
- [ ] Repeated requests to same endpoint (50+ times)
- [ ] Downloads of suspicious files (.exe, .ps1, .vbs, .scr)
- [ ] Unusual HTTP methods (CONNECT to non-proxies)

---

## 📚 Wireshark Commands Reference

### DNS Filters
```bash
# Show all DNS traffic
dns

# DNS queries only (no responses)
dns.flags.response == 0

# DNS responses only
dns.flags.response == 1

# Long domain names (adjust threshold)
dns.qry.name.len > 50
dns.qry.name.len > 100

# Failed lookups (NXDOMAIN)
dns.flags.rcode == 3

# Specific TLDs
dns.qry.name contains ".xyz"
dns.qry.name contains ".top"
dns.qry.name contains ".tk"

# DNS from specific source
ip.src == 172.20.10.3 && dns

# TXT record queries (potential C2)
dns.qry.type == 16

# PTR queries (reverse DNS)
dns.qry.type == 12

### HTTP Filters

# Show all HTTP traffic
http

# Only HTTP requests
http.request

# Only HTTP responses
http.response

# Specific methods
http.request.method == "GET"
http.request.method == "POST"
http.request.method == "PUT"

# Specific host
http.host == "www.example.com"

# Show User-Agent
http.user_agent

# Authentication headers
http.authorization
http contains "Authorization: Basic"

# Specific status codes
http.response.code == 200
http.response.code == 404
http.response.code == 500

# URLs containing keywords
http.request.uri contains "password"
http.request.uri contains "login"

# Connections to IP addresses
http.request && !http.host matches "[a-zA-Z]"

# DNS and HTTP from your VM
(dns || http) && ip.src == 172.20.10.3

# Failed DNS or HTTP errors
dns.flags.rcode == 3 || http.response.code >= 400

# POST requests with large payloads
http.request.method == "POST" && http.content_length > 1000

### Analysis Workflow
1. Capture Traffic
   ↓
2. Apply Protocol Filter (dns/http)
   ↓
3. Review Statistics View
   ↓
4. Identify Anomalies
   ↓
5. Apply Targeted Filters
   ↓
6. Inspect Packet Details
   ↓
7. Follow Streams if Needed
   ↓
8. Document Findings
   ↓
9. Assess: Benign vs Suspicious
   ↓
10. Report & Recommend

### Conclusion
Successfully captured and analyzed network traffic from a Windows VM with comprehensive DNS and HTTP inspection.
Final Assessment:
✅ CLEAN - No Indicators of Compromise
Summary:
	∙	✅ No DNS tunneling detected
	∙	✅ No DGA (Domain Generation Algorithm) activity
	∙	✅ No suspicious TLDs
	∙	✅ IP address connection identified as benign (SSDP)
	∙	✅ Legitimate User-Agent strings
	∙	✅ No cleartext credentials exposed
	∙	✅ Normal browsing behavior observed
The capture demonstrates typical, benign network activity including:
	∙	Standard DNS resolution for web browsing
	∙	HTTP requests to legitimate sites (Bing search)
	∙	Windows network discovery via UPnP/SSDP
	∙	Router performing reverse DNS lookups
Skills Demonstrated:
	∙	Traffic capture and PCAP analysis
	∙	Protocol-specific filtering (DNS, HTTP)
	∙	Statistical analysis techniques
	∙	False positive identification and reduction
	∙	Threat hunting methodology
	∙	Security-focused packet inspection
