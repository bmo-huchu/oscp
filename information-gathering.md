# OSCP Information Gathering Cheat Sheet

## 📋 Penetration Testing Lifecycle
1. **Defining the Scope**
2. **Information Gathering**
3. **Vulnerability Detection**
4. **Initial Foothold**
5. **Privilege Escalation**
6. **Lateral Movement**
7. **Reporting/Analysis**
8. **Lessons Learned/Remediation**

---

## 🔍 Passive Information Gathering

### Whois Enumeration
```bash
# Basic whois lookup
whois example.com
whois example.com -h 192.168.50.251

# Reverse whois lookup
whois <IP_ADDRESS>

# Extract useful info
whois example.com | grep -E "(Email|Phone|Name|Address)"
```

### Google Dorking
```bash
# Site-specific search
site:example.com

# File type search
site:example.com filetype:txt
site:example.com filetype:pdf
site:example.com filetype:xls
site:example.com ext:php
site:example.com ext:asp
site:example.com ext:jsp

# Exclude content
site:example.com -filetype:html

# Directory listings
intitle:"index of" "parent directory"
intitle:"index of" site:example.com

# Login pages
site:example.com inurl:login
site:example.com intitle:login

# Admin panels
site:example.com inurl:admin
site:example.com intitle:"admin panel"

# Configuration files
site:example.com filetype:conf
site:example.com filetype:ini
site:example.com filetype:xml

# Backup files
site:example.com filetype:bak
site:example.com filetype:old
site:example.com filetype:backup

# Database files
site:example.com filetype:sql
site:example.com filetype:db

# Log files
site:example.com filetype:log

# Combine operators
site:example.com filetype:txt -www
```

### Email Harvesting
```bash
# theHarvester
theHarvester -d example.com -b google
theHarvester -d example.com -b bing
theHarvester -d example.com -b linkedin
theHarvester -d example.com -b all

# Manual email pattern discovery
# firstname.lastname@example.com
# first.last@example.com
# flast@example.com
```

### Subdomain Enumeration
```bash
# Sublist3r
sublist3r -d example.com

# Amass
amass enum -d example.com

# Certificate transparency logs
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# Google dorking for subdomains
site:*.example.com
```

### GitHub Reconnaissance
```bash
# Search patterns
filename:users
filename:password
filename:config
filename:.env
filename:id_rsa
filename:id_dsa

# Code search
"example.com" password
"example.com" api_key
"example.com" secret

# Organization search
org:targetcompany

# Automated tools
git clone https://github.com/michenriksen/gitrob.git
git clone https://github.com/zricethezav/gitleaks.git
```

### Social Media Intelligence
```bash
# LinkedIn enumeration
site:linkedin.com "Company Name"
site:linkedin.com inurl:company/company-name

# Professional networks
site:github.com "example.com"
site:stackoverflow.com "example.com"
```

### Netcraft
- Visit: https://searchdns.netcraft.com
- Search for: `*.target.com`
- Gather: subdomains, technologies, hosting info

### Shodan
```bash
# Search by hostname
hostname:example.com

# Search by service
port:22
http.title:"login"
ssl:"example.com"

# Shodan CLI
shodan search "hostname:example.com"
shodan host <IP_ADDRESS>
```

---

## 🎯 Active Information Gathering

### DNS Enumeration

#### Basic DNS Queries
```bash
# A record lookup
host www.example.com
host -t mx example.com
host -t txt example.com
host -t ns example.com
host -t cname example.com

# Reverse lookup
host <IP_ADDRESS>

# Zone transfer attempt
host -l example.com ns1.example.com
dig axfr example.com @ns1.example.com
```

#### DNS Brute Force
```bash
# Manual brute force
for ip in $(cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt); do host $ip.example.com; done

# Using dnsrecon
dnsrecon -d example.com -t std
dnsrecon -d example.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
dnsrecon -d example.com -t axfr

# Using dnsenum
dnsenum example.com
dnsenum --dnsserver ns1.example.com example.com

# Using fierce
fierce -dns example.com

# Using gobuster for DNS
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

#### Windows DNS Enumeration
```cmd
# nslookup
nslookup example.com
nslookup -type=MX example.com
nslookup -type=TXT info.example.com 192.168.50.151
nslookup -type=NS example.com

# PowerShell DNS resolution
Resolve-DnsName example.com
Resolve-DnsName example.com -Type MX
```

### Port Scanning & Network Discovery

#### Initial Network Discovery
```bash
# Quick ping sweep
nmap -sn 192.168.1.0/24
fping -g 192.168.1.0/24
fping -f targets.txt

# ARP scan (local network)
arp-scan -l
netdiscover -r 192.168.1.0/24
```

#### Comprehensive Port Scanning
```bash
# Quick scan (top 1000 ports)
nmap -T4 <target>

# All TCP ports
nmap -p- <target>
nmap -p 1-65535 <target>

# Top ports
nmap --top-ports 100 <target>
nmap --top-ports 1000 <target>

# UDP scan (slow but important)
nmap -sU <target>
nmap -sU --top-ports 100 <target>

# Combined UDP/TCP
nmap -sU -sS <target>

# Stealth scan
sudo nmap -sS <target>

# TCP connect scan (when no root)
nmap -sT <target>

# Comprehensive service scan
nmap -sC -sV -O <target>
nmap -A <target>

# Fast aggressive scan
nmap -T4 -A -v <target>

# Scan specific ports
nmap -p 80,443,8080,8443 <target>
nmap -p 21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900 <target>

# Output options
nmap -oA scan_results <target>  # All formats
nmap -oG scan_results.gnmap <target>  # Greppable
nmap -oN scan_results.nmap <target>   # Normal
nmap -oX scan_results.xml <target>    # XML
```

#### Advanced Nmap Techniques
```bash
# Timing templates (0-5, 4 is aggressive)
nmap -T4 <target>

# Fragment packets (firewall evasion)
nmap -f <target>

# Decoy scan
nmap -D RND:10 <target>

# Source port specification
nmap --source-port 53 <target>

# Scan through proxy
nmap --proxies http://proxy:8080 <target>

# IPv6 scanning
nmap -6 <target>

# Scan with custom data length
nmap --data-length 25 <target>
```

#### Masscan (Fast Alternative)
```bash
# Install masscan
sudo apt install masscan

# Fast scan
masscan -p1-65535 192.168.1.0/24 --rate=1000
masscan -p80,443 192.168.1.0/24 --rate=1000
```

#### Netcat Port Scanning
```bash
# TCP scan
nc -nvv -w 1 -z <target> <port-range>
nc -nvv -w 1 -z 192.168.1.100 1-1000

# UDP scan
nc -nv -u -z -w 1 <target> <port-range>

# Banner grabbing
nc -nv <target> <port>
```

#### PowerShell Port Scanning (Windows)
```powershell
# Test single port
Test-NetConnection -Port 445 192.168.1.100

# Port range scan
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.1.100", $_)) "TCP port $_ is open"} 2>$null

# Specific port list
@(21,22,23,25,53,80,110,135,139,143,443,993,995,1723,3306,3389,5432,5900) | % {Test-NetConnection -Port $_ 192.168.1.100 -InformationLevel Quiet}
```

### Nmap Scripting Engine (NSE)

#### Default Scripts
```bash
# Run default scripts
nmap -sC <target>
nmap --script default <target>

# Safe scripts only
nmap --script safe <target>

# All scripts (be careful!)
nmap --script all <target>
```

#### HTTP Enumeration Scripts
```bash
# Basic HTTP info
nmap --script http-headers <target>
nmap --script http-methods <target>
nmap --script http-title <target>

# Directory enumeration
nmap --script http-enum <target>

# Common vulnerabilities
nmap --script http-vuln-* <target>

# Specific vulnerabilities
nmap --script http-shellshock <target>
nmap --script http-heartbleed <target>

# WordPress enumeration
nmap --script http-wordpress-enum <target>

# Form-based authentication
nmap --script http-form-brute <target>
```

#### SMB Enumeration Scripts
```bash
# OS detection
nmap --script smb-os-discovery <target>

# Share enumeration
nmap --script smb-enum-shares <target>
nmap --script smb-enum-shares --script-args smbuser=guest <target>

# User enumeration
nmap --script smb-enum-users <target>

# Security mode
nmap --script smb-security-mode <target>

# Vulnerabilities
nmap --script smb-vuln-* <target>
nmap --script smb-vuln-ms17-010 <target>  # EternalBlue

# Brute force
nmap --script smb-brute <target>
```

#### Database Scripts
```bash
# MySQL
nmap --script mysql-info <target>
nmap --script mysql-enum <target>
nmap --script mysql-brute <target>

# MSSQL
nmap --script ms-sql-info <target>
nmap --script ms-sql-ntlm-info <target>
nmap --script ms-sql-brute <target>

# Oracle
nmap --script oracle-sid-brute <target>
```

#### SSH Scripts
```bash
# SSH info
nmap --script ssh2-enum-algos <target>
nmap --script ssh-hostkey <target>

# SSH brute force
nmap --script ssh-brute <target>
```

### Web Application Enumeration

#### Directory and File Discovery
```bash
# Gobuster (fast)
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php,html,txt,js
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Dirb
dirb http://target.com
dirb http://target.com /usr/share/seclists/Discovery/Web-Content/common.txt

# Ffuf (fast)
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://target.com/FUZZ
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://target.com/FUZZ -e .php,.html,.txt

# Wfuzz
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 http://target.com/FUZZ

# Dirsearch
dirsearch -u http://target.com
dirsearch -u http://target.com -e php,html,js,txt
```

#### Technology Stack Identification
```bash
# Whatweb
whatweb http://target.com
whatweb -v http://target.com

# WAPPalyzer CLI
wappalyzer http://target.com

# Manual banner grabbing
curl -I http://target.com
wget --server-response --spider http://target.com

# Nikto
nikto -h http://target.com
```

#### CMS Enumeration
```bash
# WordPress
wpscan --url http://target.com --enumerate p,t,u

# Joomla
joomscan -u http://target.com

# Drupal
droopescan scan drupal -u http://target.com
```

### Service-Specific Enumeration

#### FTP Enumeration (Port 21)
```bash
# Basic connection
ftp <target>
# Try anonymous:anonymous

# Nmap scripts
nmap --script ftp-anon <target>
nmap --script ftp-brute <target>

# Check for anonymous access
echo "anonymous" | nc <target> 21
```

#### SSH Enumeration (Port 22)
```bash
# Version detection
ssh -V <target>
nc <target> 22

# User enumeration (CVE-2018-15473)
python ssh-username-enum.py <target> <userlist>

# Nmap scripts
nmap --script ssh2-enum-algos <target>
nmap --script ssh-hostkey <target>
```

#### Telnet Enumeration (Port 23)
```bash
# Connect
telnet <target>

# Nmap banner grab
nmap --script banner <target> -p 23
```

#### SMTP Enumeration (Port 25)
```bash
# Manual enumeration
nc -nv <target> 25
telnet <target> 25

# SMTP commands
HELO test
VRFY root
VRFY admin
EXPN root

# Nmap scripts
nmap --script smtp-enum-users <target>
nmap --script smtp-commands <target>

# smtp-user-enum
smtp-user-enum -M VRFY -U users.txt -t <target>
```

#### DNS Enumeration (Port 53)
```bash
# Zone transfer
dig axfr @<target> <domain>
host -l <domain> <target>

# Reverse lookup
dig -x <target>

# Nmap scripts
nmap --script dns-zone-transfer <target>
```

#### HTTP/HTTPS Enumeration (Ports 80/443)
```bash
# Basic enumeration
curl -I http://<target>
wget --server-response --spider http://<target>

# SSL certificate info
openssl s_client -connect <target>:443 < /dev/null
sslscan <target>

# Check for common files
curl http://<target>/robots.txt
curl http://<target>/sitemap.xml
curl http://<target>/.htaccess
curl http://<target>/admin
curl http://<target>/backup
```

#### POP3 Enumeration (Port 110)
```bash
# Connect
telnet <target> 110

# Commands
USER username
PASS password
LIST
```

#### RPC Enumeration (Port 111)
```bash
# RPC info
rpcinfo -p <target>
rpcinfo -T tcp <target>

# Nmap scripts
nmap --script rpc-grind <target>
```

#### NetBIOS/SMB Enumeration (Ports 135, 139, 445)
```bash
# Basic enumeration
enum4linux <target>
enum4linux -a <target>

# SMB client
smbclient -L //<target>
smbclient -L //<target> -U guest
smbclient -N -L //<target>

# rpcclient
rpcclient -U "" <target>
rpcclient> enumdomusers
rpcclient> enumdomgroups

# nbtscan
nbtscan <target>
nbtscan -r 192.168.1.0/24

# Windows commands
net view \\<target> /all
```

#### LDAP Enumeration (Port 389)
```bash
# ldapsearch
ldapsearch -x -h <target> -s base
ldapsearch -x -h <target> -b "dc=example,dc=com"

# Nmap scripts
nmap --script ldap-search <target>
nmap --script ldap-rootdse <target>
```

#### HTTPS/SSL Enumeration (Port 443)
```bash
# SSL info
sslscan <target>
sslyze <target>

# Certificate details
openssl s_client -connect <target>:443 < /dev/null 2>/dev/null | openssl x509 -text
```

#### SNMP Enumeration (Port 161)
```bash
# Basic enumeration
snmpwalk -c public -v1 <target>
snmpwalk -c private -v1 <target>

# Community string brute force
onesixtyone -c community.txt <target>

# Specific OID queries
snmpwalk -c public -v1 <target> 1.3.6.1.4.1.77.1.2.25         # Users
snmpwalk -c public -v1 <target> 1.3.6.1.2.1.25.4.2.1.2        # Processes
snmpwalk -c public -v1 <target> 1.3.6.1.2.1.25.6.3.1.2        # Software
snmpwalk -c public -v1 <target> 1.3.6.1.2.1.6.13.1.3          # TCP ports

# snmp-check
snmp-check <target>
```

#### LDAPS Enumeration (Port 636)
```bash
# LDAPS connection
ldapsearch -x -H ldaps://<target> -s base
```

#### Database Enumeration
```bash
# MySQL (Port 3306)
mysql -h <target> -u root -p
nmap --script mysql-info <target>

# MSSQL (Port 1433)
sqsh -S <target> -U sa
nmap --script ms-sql-info <target>

# PostgreSQL (Port 5432)
psql -h <target> -U postgres
nmap --script pgsql-brute <target>

# Oracle (Port 1521)
sqlplus sys@<target>:1521 as sysdba
nmap --script oracle-sid-brute <target>
```

#### VNC Enumeration (Port 5900)
```bash
# VNC viewer
vncviewer <target>

# Nmap scripts
nmap --script vnc-info <target>
nmap --script vnc-brute <target>
```

#### NFS Enumeration (Port 2049)
```bash
# Show mounts
showmount -e <target>

# Mount NFS
mkdir /tmp/nfs
mount -t nfs <target>:/path /tmp/nfs

# Nmap scripts
nmap --script nfs-ls <target>
nmap --script nfs-showmount <target>
```

#### Key SNMP OIDs
| OID | Description |
|-----|-------------|
| 1.3.6.1.2.1.25.1.6.0 | System Processes |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name |
| 1.3.6.1.4.1.77.1.2.25 | User Accounts |
| 1.3.6.1.2.1.6.13.1.3 | TCP Local Ports |

### Living Off The Land (Windows)

#### PowerShell Enumeration
```powershell
# Network discovery
Get-NetNeighbor
Get-NetAdapter
Get-NetRoute

# Domain information
Get-WmiObject -Class Win32_ComputerSystem
Get-ADDomain
Get-ADUser -Filter *

# Service enumeration
Get-Service
Get-Process
Get-WmiObject -Class Win32_Service

# Network connections
Get-NetTCPConnection
netstat -an

# Shares
Get-WmiObject -Class Win32_Share
net share

# Scheduled tasks
Get-ScheduledTask
schtasks /query

# Registry enumeration
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
```

#### CMD Commands (Windows)
```cmd
# Network info
ipconfig /all
netstat -an
arp -a

# System info
systeminfo
whoami /all
net user
net group
net localgroup

# Shares and drives
net share
net use
wmic logicaldisk get size,freespace,caption

# Services
sc query
wmic service list brief

# Processes
tasklist
wmic process list brief
```

---

## 🤖 Automated Tools

### AutoRecon
```bash
# Install
sudo python3 -m pip install autorecon

# Run
autorecon <target>
autorecon -t <targets.txt>
autorecon --heartbeat 60 <target>
```

### nmapAutomator
```bash
# Clone
git clone https://github.com/21y4d/nmapAutomator.git

# Run
./nmapAutomator.sh <target> All
./nmapAutomator.sh <target> Basic
./nmapAutomator.sh <target> Heavy
```

### Legion
```bash
# Install and run
sudo apt install legion
legion
```

---

## 📝 Quick Reference Commands

### Network Discovery One-Liners
```bash
# Quick alive check
nmap -sn 192.168.1.0/24 | grep -E "Nmap scan report|MAC Address"

# Fast port scan top 1000
nmap -T4 -F <target> --open

# Fast comprehensive scan
nmap -T4 -A -v <target> --open

# All TCP ports (fast)
nmap -p- --min-rate=1000 -T4 <target>

# Quick UDP scan
nmap -sU --top-ports 100 --open <target>
```

### Service-Specific Quick Scans
```bash
# Web servers
nmap -p 80,443,8080,8443 --script http-enum <target>

# Database services
nmap -p 1433,3306,5432,1521 --script "*-info" <target>

# Mail services
nmap -p 25,110,143,993,995 --script "*-info" <target>

# File sharing
nmap -p 21,22,139,445,2049 --script "*-enum*" <target>

# Remote access
nmap -p 22,23,3389,5900 <target>
```

### Grep-fu for Results
```bash
# Extract open ports from nmap
grep -E "^[0-9]+/(tcp|udp)" nmap_output.txt

# Extract IPs with open ports
grep -B 2 "open" nmap_output.txt | grep "Nmap scan report"

# Find specific services
grep -i "http\|ssh\|ftp\|smtp" nmap_output.txt
```

---

## 🔧 Environment Setup

### Essential Tools Installation
```bash
# Update repositories
sudo apt update && sudo apt upgrade -y

# Core tools
sudo apt install -y nmap netcat-traditional dnsrecon dnsenum nbtscan onesixtyone snmp snmp-mibs-downloader smbclient rpcclient enum4linux

# Web enumeration
sudo apt install -y gobuster dirb nikto wpscan

# Additional tools
sudo apt install -y whatweb sslscan sslyze sublist3r theHarvester

# Install SecLists
sudo apt install seclists
# Or manually: git clone https://github.com/danielmiessler/SecLists.git

# Python tools
pip3 install requests beautifulsoup4 dnspython
```

### Useful Wordlists Locations
```bash
# SecLists
/usr/share/seclists/Discovery/DNS/
/usr/share/seclists/Discovery/Web-Content/
/usr/share/seclists/Usernames/
/usr/share/seclists/Passwords/

# Dirb
/usr/share/dirb/wordlists/

# Built-in wordlists
/usr/share/wordlists/

# Custom wordlist creation
cewl http://target.com > custom_wordlist.txt
```

---

## ⚠️ OSCP Exam Considerations

### Time Management
1. **Start with AutoRecon** for initial enumeration
2. **Parallel scanning**: Run different tools simultaneously
3. **Focus on high-value ports** first: 21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900
4. **Document everything** as you go

### Common Port Priorities
```bash
# High Priority (attack vectors)
21    # FTP - Anonymous access, file upload
22    # SSH - Key authentication, user enum
23    # Telnet - Clear text credentials
25    # SMTP - User enumeration
53    # DNS - Zone transfers, subdomain enum
80    # HTTP - Web vulnerabilities
135   # RPC - Windows enumeration
139   # NetBIOS - SMB enumeration
443   # HTTPS - Certificate info, web vulnerabilities
445   # SMB - Share enumeration, null sessions
1433  # MSSQL - Database access
3306  # MySQL - Database access
3389  # RDP - Remote desktop
5432  # PostgreSQL - Database access

# Medium Priority
110   # POP3 - Email access
111   # RPC - Service enumeration
143   # IMAP - Email access
161   # SNMP - System information
993   # IMAPS - Secure email
995   # POP3S - Secure email
2049  # NFS - File sharing
5900  # VNC - Remote desktop
```

### Stealth Considerations
```bash
# Slower but stealthier
nmap -T2 <target>

# Avoid detection
nmap -f <target>                    # Fragment packets
nmap -D RND:10 <target>             # Decoy scan
nmap --source-port 53 <target>      # Spoof source port
nmap --data-length 25 <target>      # Random data length
```

### Output Management
```bash
# Organized output structure
mkdir enum_results
cd enum_results

# Nmap with all output formats
nmap -oA initial_scan <target>

# Grep-friendly results
nmap -oG quick_scan.gnmap <target>

# Parse results
grep "open" *.gnmap | cut -d' ' -f2 | sort -u > live_hosts.txt
```

### Documentation Template
```bash
# Create enumeration notes template
cat > enum_notes.md << EOF
# Target: <IP_ADDRESS>

## Network Information
- OS: 
- Open Ports: 
- Services: 

## Web Applications
- Technologies: 
- Directories: 
- Vulnerabilities: 

## Potential Attack Vectors
1. 
2. 
3. 

## Credentials Found
- 

## Notes
- 
EOF
```

---

## 🎯 Advanced Techniques

### Certificate Analysis for Subdomain Discovery
```bash
# Extract domains from SSL certificates
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -text | grep -oE '[a-zA-Z0-9.-]+\.target\.com' | sort -u

# Certificate transparency logs
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

### Advanced SMB Enumeration
```bash
# Null session enumeration
rpcclient -U "" -N <target>
smbclient -N -L //<target>

# Share enumeration with credentials
smbmap -H <target> -u guest
smbmap -H <target> -u null -p ""

# Enum4linux comprehensive scan
enum4linux -a <target>
```

### LDAP Advanced Queries
```bash
# Anonymous bind
ldapsearch -x -h <target> -s base namingcontexts

# Extract all users
ldapsearch -x -h <target> -b "dc=example,dc=com" "(objectclass=user)" sAMAccountName

# Extract groups
ldapsearch -x -h <target> -b "dc=example,dc=com" "(objectclass=group)" cn
```

This comprehensive cheat sheet now includes all the critical areas needed for OSCP success, with practical examples and time-saving techniques specifically tailored for the exam environment.
