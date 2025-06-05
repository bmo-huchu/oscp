# OSCP 정보 수집 치트시트

## 📋 모의해킹 생명주기
1. **범위 정의** (Defining the Scope)
2. **정보 수집** (Information Gathering)
3. **취약점 탐지** (Vulnerability Detection)
4. **초기 침투** (Initial Foothold)
5. **권한 상승** (Privilege Escalation)
6. **측면 이동** (Lateral Movement)
7. **보고서 작성/분석** (Reporting/Analysis)
8. **교훈 도출/개선** (Lessons Learned/Remediation)

---

## 🔍 수동적 정보 수집 (Passive Information Gathering)

### Whois 조회
```bash
# 기본 whois 조회
whois example.com
whois example.com -h 192.168.50.251

# 역방향 whois 조회 (IP → 도메인)
whois <IP주소>

# 유용한 정보 추출
whois example.com | grep -E "(Email|Phone|Name|Address)"
```

### 구글 도킹 (Google Dorking)
```bash
# 특정 사이트 검색
site:example.com

# 파일 형식별 검색
site:example.com filetype:txt     # 텍스트 파일
site:example.com filetype:pdf     # PDF 파일
site:example.com filetype:xls     # 엑셀 파일
site:example.com ext:php          # PHP 파일
site:example.com ext:asp          # ASP 파일
site:example.com ext:jsp          # JSP 파일

# 특정 콘텐츠 제외
site:example.com -filetype:html

# 디렉토리 리스팅 찾기
intitle:"index of" "parent directory"
intitle:"index of" site:example.com

# 로그인 페이지 찾기
site:example.com inurl:login
site:example.com intitle:login

# 관리자 패널 찾기
site:example.com inurl:admin
site:example.com intitle:"admin panel"

# 설정 파일 찾기
site:example.com filetype:conf    # 설정 파일
site:example.com filetype:ini     # 초기화 파일
site:example.com filetype:xml     # XML 파일

# 백업 파일 찾기
site:example.com filetype:bak     # 백업 파일
site:example.com filetype:old     # 구 버전 파일
site:example.com filetype:backup  # 백업 파일

# 데이터베이스 파일 찾기
site:example.com filetype:sql     # SQL 파일
site:example.com filetype:db      # 데이터베이스 파일

# 로그 파일 찾기
site:example.com filetype:log     # 로그 파일

# 연산자 조합 사용
site:example.com filetype:txt -www
```

### 이메일 수집
```bash
# theHarvester 사용
theHarvester -d example.com -b google    # 구글에서 검색
theHarvester -d example.com -b bing      # 빙에서 검색
theHarvester -d example.com -b linkedin  # 링크드인에서 검색
theHarvester -d example.com -b all       # 모든 소스에서 검색

# 일반적인 이메일 패턴
# firstname.lastname@example.com
# first.last@example.com
# flast@example.com
```

### 서브도메인 열거
```bash
# Sublist3r 사용
sublist3r -d example.com

# Amass 사용
amass enum -d example.com

# 인증서 투명성 로그 활용
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# 구글 도킹으로 서브도메인 찾기
site:*.example.com
```

### GitHub 정찰
```bash
# 검색 패턴
filename:users        # 사용자 목록 파일
filename:password     # 패스워드 파일
filename:config       # 설정 파일
filename:.env         # 환경 변수 파일
filename:id_rsa       # SSH 개인키
filename:id_dsa       # DSA 개인키

# 코드 검색
"example.com" password    # 해당 도메인의 패스워드
"example.com" api_key     # API 키
"example.com" secret      # 비밀 정보

# 조직 검색
org:targetcompany

# 자동화 도구
git clone https://github.com/michenriksen/gitrob.git
git clone https://github.com/zricethezav/gitleaks.git
```

### 소셜 미디어 정보 수집
```bash
# 링크드인 정보 수집
site:linkedin.com "회사명"
site:linkedin.com inurl:company/company-name

# 전문가 네트워크
site:github.com "example.com"
site:stackoverflow.com "example.com"
```

### Netcraft 활용
- 방문: https://searchdns.netcraft.com
- 검색: `*.target.com`
- 수집 정보: 서브도메인, 기술 스택, 호스팅 정보

### Shodan 활용
```bash
# 호스트명으로 검색
hostname:example.com

# 서비스별 검색
port:22                    # SSH 서비스
http.title:"login"         # 로그인 제목 페이지
ssl:"example.com"          # SSL 인증서

# Shodan CLI 사용
shodan search "hostname:example.com"
shodan host <IP주소>
```

---

## 🎯 능동적 정보 수집 (Active Information Gathering)

### DNS 정보 수집

#### 기본 DNS 조회
```bash
# A 레코드 조회 (도메인 → IP)
host www.example.com
host -t mx example.com        # 메일 서버 조회
host -t txt example.com       # TXT 레코드 조회
host -t ns example.com        # 네임서버 조회
host -t cname example.com     # CNAME 레코드 조회

# 역방향 조회 (IP → 도메인)
host <IP주소>

# 영역 전송 시도 (Zone Transfer)
host -l example.com ns1.example.com
dig axfr example.com @ns1.example.com
```

#### DNS 브루트 포스
```bash
# 수동 브루트 포스
for ip in $(cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt); do host $ip.example.com; done

# dnsrecon 사용
dnsrecon -d example.com -t std              # 표준 스캔
dnsrecon -d example.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt  # 브루트포스
dnsrecon -d example.com -t axfr              # 영역 전송 시도

# dnsenum 사용
dnsenum example.com
dnsenum --dnsserver ns1.example.com example.com

# fierce 사용
fierce -dns example.com

# gobuster로 DNS 브루트포스
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

#### Windows DNS 정보 수집
```cmd
# nslookup 사용
nslookup example.com
nslookup -type=MX example.com
nslookup -type=TXT info.example.com 192.168.50.151
nslookup -type=NS example.com

# PowerShell DNS 해결
Resolve-DnsName example.com
Resolve-DnsName example.com -Type MX
```

### 포트 스캐닝 및 네트워크 발견

#### 초기 네트워크 발견
```bash
# 빠른 핑 스윕
nmap -sn 192.168.1.0/24       # 핑으로 살아있는 호스트 확인
fping -g 192.168.1.0/24       # fping으로 범위 스캔
fping -f targets.txt          # 파일에서 대상 읽기

# ARP 스캔 (로컬 네트워크)
arp-scan -l                   # 로컬 네트워크 ARP 스캔
netdiscover -r 192.168.1.0/24 # 네트워크 디스커버리
```

#### 종합적인 포트 스캐닝
```bash
# 빠른 스캔 (상위 1000포트)
nmap -T4 <대상>

# 모든 TCP 포트
nmap -p- <대상>               # 전체 포트 범위
nmap -p 1-65535 <대상>        # 명시적 포트 범위

# 상위 포트만
nmap --top-ports 100 <대상>   # 상위 100개 포트
nmap --top-ports 1000 <대상>  # 상위 1000개 포트

# UDP 스캔 (느리지만 중요)
nmap -sU <대상>               # UDP 스캔
nmap -sU --top-ports 100 <대상>  # 상위 UDP 포트만

# UDP/TCP 결합 스캔
nmap -sU -sS <대상>

# 스텔스 스캔
sudo nmap -sS <대상>          # SYN 스캔 (루트 권한 필요)

# TCP 연결 스캔 (루트 권한 없을 때)
nmap -sT <대상>

# 종합 서비스 스캔
nmap -sC -sV -O <대상>        # 스크립트, 버전, OS 탐지
nmap -A <대상>                # 공격적 스캔 (모든 옵션)

# 빠른 공격적 스캔
nmap -T4 -A -v <대상>

# 특정 포트 스캔
nmap -p 80,443,8080,8443 <대상>
nmap -p 21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900 <대상>

# 출력 옵션
nmap -oA scan_results <대상>  # 모든 형식으로 저장
nmap -oG scan_results.gnmap <대상>  # Grep 가능한 형식
nmap -oN scan_results.nmap <대상>   # 일반 형식
nmap -oX scan_results.xml <대상>    # XML 형식
```

#### 고급 Nmap 기법
```bash
# 타이밍 템플릿 (0-5, 4가 공격적)
nmap -T4 <대상>

# 패킷 단편화 (방화벽 우회)
nmap -f <대상>

# 미끼 스캔
nmap -D RND:10 <대상>         # 랜덤 미끼 10개
nmap -D 192.168.1.100,192.168.1.101,ME <대상>  # 특정 미끼 IP

# 소스 포트 지정
nmap --source-port 53 <대상>  # DNS 포트로 위장
nmap --source-port 80 <대상>  # HTTP 포트로 위장

# 프록시를 통한 스캔
nmap --proxies http://proxy:8080 <대상>

# IPv6 스캔
nmap -6 <대상>

# 사용자 정의 데이터 길이
nmap --data-length 25 <대상>
```

#### Masscan (빠른 대안)
```bash
# Masscan 설치
sudo apt install masscan

# 빠른 스캔
masscan -p1-65535 192.168.1.0/24 --rate=1000   # 전체 포트
masscan -p80,443 192.168.1.0/24 --rate=1000    # 웹 포트만
```

#### Netcat 포트 스캐닝
```bash
# TCP 스캔
nc -nvv -w 1 -z <대상> <포트범위>
nc -nvv -w 1 -z 192.168.1.100 1-1000

# UDP 스캔
nc -nv -u -z -w 1 <대상> <포트범위>

# 배너 그래빙
nc -nv <대상> <포트>
```

#### PowerShell 포트 스캐닝 (Windows)
```powershell
# 단일 포트 테스트
Test-NetConnection -Port 445 192.168.1.100

# 포트 범위 스캔
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.1.100", $_)) "TCP port $_ is open"} 2>$null

# 특정 포트 목록
@(21,22,23,25,53,80,110,135,139,143,443,993,995,1723,3306,3389,5432,5900) | % {Test-NetConnection -Port $_ 192.168.1.100 -InformationLevel Quiet}
```

### Nmap 스크립팅 엔진 (NSE)

#### 기본 스크립트
```bash
# 기본 스크립트 실행
nmap -sC <대상>
nmap --script default <대상>

# 안전한 스크립트만
nmap --script safe <대상>

# 모든 스크립트 (주의!)
nmap --script all <대상>
```

#### HTTP 열거 스크립트
```bash
# 기본 HTTP 정보
nmap --script http-headers <대상>      # HTTP 헤더 정보
nmap --script http-methods <대상>      # 허용된 HTTP 메소드
nmap --script http-title <대상>        # 페이지 제목

# 디렉토리 열거
nmap --script http-enum <대상>

# 일반적인 취약점
nmap --script http-vuln-* <대상>

# 특정 취약점
nmap --script http-shellshock <대상>   # Shellshock 취약점
nmap --script http-heartbleed <대상>   # Heartbleed 취약점

# WordPress 열거
nmap --script http-wordpress-enum <대상>

# 폼 기반 인증 브루트포스
nmap --script http-form-brute <대상>
```

#### SMB 열거 스크립트
```bash
# OS 탐지
nmap --script smb-os-discovery <대상>

# 공유 폴더 열거
nmap --script smb-enum-shares <대상>
nmap --script smb-enum-shares --script-args smbuser=guest <대상>

# 사용자 열거
nmap --script smb-enum-users <대상>

# 보안 모드
nmap --script smb-security-mode <대상>

# 취약점
nmap --script smb-vuln-* <대상>
nmap --script smb-vuln-ms17-010 <대상>  # EternalBlue

# 브루트포스
nmap --script smb-brute <대상>
```

#### 데이터베이스 스크립트
```bash
# MySQL
nmap --script mysql-info <대상>        # MySQL 정보
nmap --script mysql-enum <대상>        # MySQL 열거
nmap --script mysql-brute <대상>       # MySQL 브루트포스

# MSSQL
nmap --script ms-sql-info <대상>       # MSSQL 정보
nmap --script ms-sql-ntlm-info <대상>  # NTLM 정보
nmap --script ms-sql-brute <대상>      # MSSQL 브루트포스

# Oracle
nmap --script oracle-sid-brute <대상>  # Oracle SID 브루트포스
```

#### SSH 스크립트
```bash
# SSH 정보
nmap --script ssh2-enum-algos <대상>   # 지원 알고리즘
nmap --script ssh-hostkey <대상>       # 호스트 키

# SSH 브루트포스
nmap --script ssh-brute <대상>
```

### 웹 애플리케이션 열거

#### 디렉토리 및 파일 발견
```bash
# Gobuster (빠름)
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php,html,txt,js

# Dirb
dirb http://target.com
dirb http://target.com /usr/share/seclists/Discovery/Web-Content/common.txt

# Ffuf (빠름)
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://target.com/FUZZ
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://target.com/FUZZ -e .php,.html,.txt

# Wfuzz
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 http://target.com/FUZZ

# Dirsearch
dirsearch -u http://target.com
dirsearch -u http://target.com -e php,html,js,txt
```

#### 기술 스택 식별
```bash
# Whatweb
whatweb http://target.com         # 기본 정보
whatweb -v http://target.com      # 상세 정보

# WAPPalyzer CLI
wappalyzer http://target.com

# 수동 배너 그래빙
curl -I http://target.com         # HTTP 헤더만
wget --server-response --spider http://target.com

# Nikto
nikto -h http://target.com
```

#### CMS 열거
```bash
# WordPress
wpscan --url http://target.com --enumerate p,t,u

# Joomla
joomscan -u http://target.com

# Drupal
droopescan scan drupal -u http://target.com
```

### 서비스별 열거

#### FTP 열거 (포트 21)
```bash
# 기본 연결
ftp <대상>
# anonymous:anonymous 시도

# Nmap 스크립트
nmap --script ftp-anon <대상>     # 익명 접근 확인
nmap --script ftp-brute <대상>    # 브루트포스

# 익명 접근 확인
echo "anonymous" | nc <대상> 21
```

#### SSH 열거 (포트 22)
```bash
# 버전 탐지
ssh -V <대상>
nc <대상> 22

# 사용자 열거 (CVE-2018-15473)
python ssh-username-enum.py <대상> <사용자목록>

# Nmap 스크립트
nmap --script ssh2-enum-algos <대상>
nmap --script ssh-hostkey <대상>
```

#### Telnet 열거 (포트 23)
```bash
# 연결
telnet <대상>

# Nmap 배너 그래빙
nmap --script banner <대상> -p 23
```

#### SMTP 열거 (포트 25)
```bash
# 수동 열거
nc -nv <대상> 25
telnet <대상> 25

# SMTP 명령어
HELO test
VRFY root         # 사용자 확인
VRFY admin
EXPN root         # 메일링 리스트 확장

# Nmap 스크립트
nmap --script smtp-enum-users <대상>
nmap --script smtp-commands <대상>

# smtp-user-enum
smtp-user-enum -M VRFY -U users.txt -t <대상>
```

#### DNS 열거 (포트 53)
```bash
# 영역 전송
dig axfr @<대상> <도메인>
host -l <도메인> <대상>

# 역방향 조회
dig -x <대상>

# Nmap 스크립트
nmap --script dns-zone-transfer <대상>
```

#### HTTP/HTTPS 열거 (포트 80/443)
```bash
# 기본 열거
curl -I http://<대상>
wget --server-response --spider http://<대상>

# SSL 인증서 정보
openssl s_client -connect <대상>:443 < /dev/null
sslscan <대상>

# 일반적인 파일 확인
curl http://<대상>/robots.txt      # 로봇 배제 파일
curl http://<대상>/sitemap.xml     # 사이트맵
curl http://<대상>/.htaccess       # 접근 제어 파일
curl http://<대상>/admin           # 관리자 디렉토리
curl http://<대상>/backup          # 백업 디렉토리
```

#### POP3 열거 (포트 110)
```bash
# 연결
telnet <대상> 110

# 명령어
USER username     # 사용자명
PASS password     # 패스워드
LIST             # 메일 목록
```

#### RPC 열거 (포트 111)
```bash
# RPC 정보
rpcinfo -p <대상>
rpcinfo -T tcp <대상>

# Nmap 스크립트
nmap --script rpc-grind <대상>
```

#### NetBIOS/SMB 열거 (포트 135, 139, 445)
```bash
# 기본 열거
enum4linux <대상>            # 종합 SMB 열거
enum4linux -a <대상>         # 모든 정보

# SMB 클라이언트
smbclient -L //<대상>         # 공유 목록
smbclient -L //<대상> -U guest    # 게스트로 접근
smbclient -N -L //<대상>      # 널 세션

# rpcclient
rpcclient -U "" <대상>        # 널 세션으로 RPC 연결
rpcclient> enumdomusers       # 도메인 사용자 열거
rpcclient> enumdomgroups      # 도메인 그룹 열거

# nbtscan
nbtscan <대상>
nbtscan -r 192.168.1.0/24

# Windows 명령어
net view \\<대상> /all        # 공유 폴더 확인
```

#### LDAP 열거 (포트 389)
```bash
# ldapsearch
ldapsearch -x -h <대상> -s base
ldapsearch -x -h <대상> -b "dc=example,dc=com"

# Nmap 스크립트
nmap --script ldap-search <대상>
nmap --script ldap-rootdse <대상>
```

#### HTTPS/SSL 열거 (포트 443)
```bash
# SSL 정보
sslscan <대상>                # SSL 설정 분석
sslyze <대상>                 # 종합 SSL 분석

# 인증서 세부 정보
openssl s_client -connect <대상>:443 < /dev/null 2>/dev/null | openssl x509 -text
```

#### SNMP 열거 (포트 161)
```bash
# 기본 열거
snmpwalk -c public -v1 <대상>     # 공개 커뮤니티 스트링
snmpwalk -c private -v1 <대상>    # 프라이빗 커뮤니티 스트링

# 커뮤니티 스트링 브루트포스
onesixtyone -c community.txt <대상>

# 특정 OID 쿼리
snmpwalk -c public -v1 <대상> 1.3.6.1.4.1.77.1.2.25         # 사용자
snmpwalk -c public -v1 <대상> 1.3.6.1.2.1.25.4.2.1.2        # 프로세스
snmpwalk -c public -v1 <대상> 1.3.6.1.2.1.25.6.3.1.2        # 소프트웨어
snmpwalk -c public -v1 <대상> 1.3.6.1.2.1.6.13.1.3          # TCP 포트

# snmp-check
snmp-check <대상>
```

#### LDAPS 열거 (포트 636)
```bash
# LDAPS 연결
ldapsearch -x -H ldaps://<대상> -s base
```

#### 데이터베이스 열거
```bash
# MySQL (포트 3306)
mysql -h <대상> -u root -p
nmap --script mysql-info <대상>

# MSSQL (포트 1433)
sqsh -S <대상> -U sa
nmap --script ms-sql-info <대상>

# PostgreSQL (포트 5432)
psql -h <대상> -U postgres
nmap --script pgsql-brute <대상>

# Oracle (포트 1521)
sqlplus sys@<대상>:1521 as sysdba
nmap --script oracle-sid-brute <대상>
```

#### VNC 열거 (포트 5900)
```bash
# VNC 뷰어
vncviewer <대상>

# Nmap 스크립트
nmap --script vnc-info <대상>
nmap --script vnc-brute <대상>
```

#### NFS 열거 (포트 2049)
```bash
# 마운트 정보 확인
showmount -e <대상>

# NFS 마운트
mkdir /tmp/nfs
mount -t nfs <대상>:/path /tmp/nfs

# Nmap 스크립트
nmap --script nfs-ls <대상>
nmap --script nfs-showmount <대상>
```

#### 주요 SNMP OID
| OID | 설명 |
|-----|-------------|
| 1.3.6.1.2.1.25.1.6.0 | 시스템 프로세스 |
| 1.3.6.1.2.1.25.4.2.1.2 | 실행 중인 프로그램 |
| 1.3.6.1.2.1.25.4.2.1.4 | 프로세스 경로 |
| 1.3.6.1.2.1.25.2.3.1.4 | 저장소 단위 |
| 1.3.6.1.2.1.25.6.3.1.2 | 소프트웨어 이름 |
| 1.3.6.1.4.1.77.1.2.25 | 사용자 계정 |
| 1.3.6.1.2.1.6.13.1.3 | TCP 로컬 포트 |

### 윈도우 환경에서의 정찰 (Living Off The Land)

#### PowerShell 열거
```powershell
# 네트워크 발견
Get-NetNeighbor               # 네트워크 이웃
Get-NetAdapter                # 네트워크 어댑터
Get-NetRoute                  # 라우팅 테이블

# 도메인 정보
Get-WmiObject -Class Win32_ComputerSystem
Get-ADDomain                  # AD 도메인 정보
Get-ADUser -Filter *          # 모든 AD 사용자

# 서비스 열거
Get-Service                   # 서비스 목록
Get-Process                   # 프로세스 목록
Get-WmiObject -Class Win32_Service

# 네트워크 연결
Get-NetTCPConnection          # TCP 연결
netstat -an                   # 네트워크 상태

# 공유 폴더
Get-WmiObject -Class Win32_Share
net share

# 스케줄된 작업
Get-ScheduledTask
schtasks /query

# 레지스트리 열거
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
```

#### CMD 명령어 (Windows)
```cmd
# 네트워크 정보
ipconfig /all                 # IP 설정 정보
netstat -an                   # 네트워크 상태
arp -a                        # ARP 테이블

# 시스템 정보
systeminfo                    # 시스템 정보
whoami /all                   # 현재 사용자 권한
net user                      # 사용자 목록
net group                     # 그룹 목록
net localgroup                # 로컬 그룹

# 공유 및 드라이브
net share                     # 공유 폴더
net use                       # 네트워크 드라이브
wmic logicaldisk get size,freespace,caption

# 서비스
sc query                      # 서비스 쿼리
wmic service list brief       # 서비스 목록

# 프로세스
tasklist                      # 작업 목록
wmic process list brief       # 프로세스 목록
```

---

## 🔬 취약점 스캐닝

### Nuclei (빠른 취약점 스캐너)
```bash
# 설치
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# 기본 스캔
nuclei -u http://target.com
nuclei -l targets.txt          # 대상 목록 파일

# 특정 템플릿
nuclei -u http://target.com -t cves/            # CVE 템플릿
nuclei -u http://target.com -t vulnerabilities/ # 취약점 템플릿
nuclei -u http://target.com -t misconfiguration/ # 설정 오류

# 템플릿 업데이트
nuclei -update-templates

# 심각도별 스캔
nuclei -u http://target.com -severity critical,high,medium
```

### OpenVAS
```bash
# Docker로 설치
docker run -d -p 9392:9392 --name openvas mikesplain/openvas

# 웹 인터페이스: https://localhost:9392
# 기본 계정: admin:admin
```

### Nessus (상용)
```bash
# 설치 및 설정
sudo dpkg -i Nessus-X.X.X-debian6_amd64.deb
sudo /bin/systemctl start nessusd.service

# 웹 인터페이스: https://localhost:8834
```

---

## 🌐 API 열거

### REST API 발견
```bash
# 일반적인 API 엔드포인트
curl http://target.com/api/
curl http://target.com/api/v1/
curl http://target.com/api/v2/
curl http://target.com/rest/
curl http://target.com/graphql

# API 문서
curl http://target.com/swagger/    # Swagger 문서
curl http://target.com/docs/       # 일반 문서
curl http://target.com/api-docs/   # API 문서
curl http://target.com/openapi.json # OpenAPI 스펙

# API용 디렉토리 브루트포스
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -u http://target.com/FUZZ
```

### GraphQL 열거
```bash
# 인트로스펙션 쿼리
curl -X POST http://target.com/graphql -H "Content-Type: application/json" -d '{"query": "{ __schema { types { name fields { name } } } }"}'

# GraphQL Voyager (시각적 탐색)
# 방문: https://apis.guru/graphql-voyager/
```

### API 테스트 도구
```bash
# Postman CLI
newman run collection.json

# REST API 퍼저
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/api/objects.txt http://target.com/api/FUZZ

# OWASP ZAP API 스캔
zap-cli quick-scan --self-contained http://target.com/api/
```

---

## ☁️ 클라우드 서비스 발견

### AWS 열거
```bash
# S3 버킷 발견
aws s3 ls s3://target-company-bucket --no-sign-request
aws s3 sync s3://target-company-bucket . --no-sign-request

# 일반적인 버킷 명명 패턴
company-name              # 회사명
company-backup            # 백업
company-logs              # 로그
company-data              # 데이터
company-dev               # 개발
company-prod              # 운영

# S3 버킷 브루트포스
gobuster s3 -w /usr/share/seclists/Discovery/Web-Content/common.txt -t company

# CloudFront 배포
dig company.cloudfront.net

# Route53 열거
dig @8.8.8.8 company.com any
```

### Azure 열거
```bash
# Azure 블롭 스토리지
https://companyname.blob.core.windows.net/
https://companyname.file.core.windows.net/

# Azure AD 발견
https://login.microsoftonline.com/company.com/.well-known/openid_configuration
```

### Google Cloud Platform
```bash
# GCP 스토리지 버킷
https://storage.googleapis.com/company-bucket/

# GCP App Engine
https://company-project.appspot.com/
```

---

## 📱 모바일 및 IoT 평가

### APK 분석 (Android)
```bash
# 도구 설치
sudo apt install apktool dex2jar

# APK 디컴파일
apktool d app.apk
d2j-dex2jar app.apk

# 문자열 추출
strings app.apk | grep -E "(http|ftp|api|key|pass|secret)"

# JADX 디컴파일러
jadx app.apk
```

### IoT 디바이스 발견
```bash
# Nmap IoT 스캔
nmap -sU -sS --script discovery 192.168.1.0/24

# 일반적인 IoT 포트
nmap -p 80,443,23,21,22,161,8080,8443,9000,5000 192.168.1.0/24

# UPnP 발견
nmap -sU -p 1900 --script upnp-info 192.168.1.0/24
```

---

## 📡 무선 평가

### WiFi 정찰
```bash
# 모니터 모드
sudo airmon-ng start wlan0

# 네트워크 발견
sudo airodump-ng wlan0mon

# 특정 네트워크 캡처
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# 블루투스 발견
hcitool scan
sudo bluetoothctl
```

---

## 🐳 컨테이너 및 오케스트레이션

### Docker 열거
```bash
# Docker API 노출
curl http://target:2376/version
curl http://target:2375/containers/json

# Docker 레지스트리
curl http://target:5000/v2/_catalog

# Kubernetes 열거
curl -k https://target:6443/api/v1/namespaces
curl -k https://target:8080/api/v1/nodes

# 컨테이너 탈출 확인
docker run --rm -it --pid=host --net=host --privileged alpine:latest
```

---

## 🏢 Active Directory 심화

### 도메인 열거
```bash
# BloodHound 수집
bloodhound-python -u username -p password -ns 192.168.1.10 -d domain.com -c all

# PowerView 동등 기능 (Linux)
ldapsearch -x -h dc.domain.com -D "user@domain.com" -W -b "dc=domain,dc=com" "(objectclass=user)" sAMAccountName

# Kerbrute 사용자 열거
kerbrute userenum --dc 192.168.1.10 -d domain.com userlist.txt

# ASREPRoast
GetNPUsers.py domain.com/ -usersfile users.txt -format hashcat -outputfile hashes.asreproast

# Kerberoasting
GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -request
```

### AD 인증서 서비스
```bash
# 인증서 템플릿 열거
certipy find -u user@domain.com -p password -dc-ip 192.168.1.10

# ESC1 - 인증서 템플릿 남용
certipy req -u user@domain.com -p password -ca 'CA-NAME' -template 'TEMPLATE-NAME' -alt 'administrator@domain.com'
```

---

## 🕵️ 고급 OSINT

### 메타데이터 분석
```bash
# ExifTool
exiftool document.pdf         # PDF 메타데이터
exiftool image.jpg            # 이미지 메타데이터

# 수동 메타데이터 추출
strings document.pdf | grep -E "(Author|Creator|Producer|Title)"
```

### 소셜 미디어 정보 수집
```bash
# Sherlock - 사용자명 조사
python3 sherlock.py target_username

# Social Mapper
python3 social_mapper.py -f list.txt -m linkedin

# LinkedIn 열거
site:linkedin.com "회사명" "소프트웨어 엔지니어"
site:linkedin.com intitle:"회사명"
```

### 고급 구글 도킹
```bash
# 회사별 정보 수집
"회사명" filetype:xls "기밀"
"회사명" filetype:doc "내부"
"회사명" inurl:sharepoint
"회사명" site:pastebin.com
"회사명" site:github.com "password"

# 기술 스택 발견
"powered by" site:target.com    # 사용 기술
"built with" site:target.com    # 빌드 기술
site:target.com inurl:wp-content  # WordPress
site:target.com inurl:joomla      # Joomla
```

---

## 🔍 매개변수 및 입력 발견

### 매개변수 퍼징
```bash
# Arjun - HTTP 매개변수 발견
arjun -u http://target.com/page

# 일반적인 매개변수명
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://target.com/page?FUZZ=test

# POST 매개변수 발견
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -d "FUZZ=test" http://target.com/page
```

### 입력 검증 테스트
```bash
# XSS 페이로드
<script>alert('XSS')</script>
"><script>alert('XSS')</script>

# SQL 인젝션 페이로드
' OR '1'='1
" OR "1"="1
'; DROP TABLE users--

# 명령어 인젝션
; id
| id
` id `
$( id )

# LDAP 인젝션
*)(uid=*))(|(uid=*
```

---

## 📊 트래픽 분석 및 모니터링

### 네트워크 트래픽 캡처
```bash
# tcpdump
sudo tcpdump -i eth0 -w capture.pcap     # 패킷 캡처
sudo tcpdump -i eth0 host target.com     # 특정 호스트
sudo tcpdump -i eth0 port 80              # 특정 포트

# Wireshark CLI
tshark -i eth0 -w capture.pcap
tshark -r capture.pcap -T fields -e ip.src -e ip.dst

# Netstat 모니터링
watch 'netstat -tuln'
ss -tuln

# 실시간 연결 모니터링
watch 'lsof -i'
```

### 로그 분석
```bash
# 일반적인 로그 위치
/var/log/apache2/access.log   # Apache 접근 로그
/var/log/nginx/access.log     # Nginx 접근 로그
/var/log/auth.log             # 인증 로그
/var/log/syslog               # 시스템 로그

# 로그 분석 명령어
tail -f /var/log/apache2/access.log                                    # 실시간 로그
grep "POST" /var/log/apache2/access.log                                # POST 요청
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -nr  # IP별 요청 수
```

---

## 🔐 크리덴셜 수집

### 크리덴셜 발견
```bash
# 파일에서 크리덴셜 검색
grep -r "password" /path/to/search/
grep -r "pass" /path/to/search/
find . -name "*.txt" -exec grep -l "password" {} \;

# 데이터베이스 연결 문자열
grep -r "connectionString" .
grep -r "jdbc:" .
grep -r "mysql://" .

# API 키 및 토큰
grep -r "api_key" .
grep -r "token" .
grep -r "secret" .

# Git 크리덴셜 노출
# .git/config 확인
# git 히스토리에서 저장된 크리덴셜 찾기
git log --oneline | head -20
```

### 브라우저 데이터 추출
```bash
# Firefox 저장된 패스워드 (접근 가능한 경우)
find ~/.mozilla/firefox/ -name "logins.json"

# Chrome 저장된 패스워드
find ~/.config/google-chrome/ -name "Login Data"

# 브라우저 히스토리
find ~/.mozilla/firefox/ -name "places.sqlite"
find ~/.config/google-chrome/ -name "History"
```

---

## 🥷 고급 회피 기법

### Nmap 회피
```bash
# 패킷 단편화
nmap -f target.com

# 미끼 사용
nmap -D RND:10 target.com                                        # 랜덤 미끼 10개
nmap -D 192.168.1.100,192.168.1.101,ME target.com              # 특정 미끼 IP

# 유휴 스캔
nmap -sI zombie_host target.com

# 소스 포트 조작
nmap --source-port 53 target.com    # DNS 포트로 위장
nmap --source-port 80 target.com    # HTTP 포트로 위장

# 타이밍 지연
nmap -T0 target.com  # 편집증적 (매우 느림)
nmap -T1 target.com  # 은밀한 (느림)

# 사용자 정의 패킷 데이터
nmap --data-length 25 target.com

# 대상 순서 무작위화
nmap --randomize-hosts 192.168.1.0/24

# MAC 주소 스푸핑
nmap --spoof-mac 0 target.com
```

### WAF 우회 기법
```bash
# 대소문자 변화
admin vs ADMIN vs AdMiN

# URL 인코딩
%61dmin = admin
%2e = .
%2f = /

# 이중 인코딩
%2561 = %61 = a

# 유니코드 인코딩
ℳ (U+2133) = M
￼ (U+FFFC) = OBJECT REPLACEMENT CHARACTER

# 매개변수 오염
?id=1&id=2

# HTTP 동사 조작
POST vs PUT vs PATCH

# Content-Type 우회
application/json vs text/plain
```

---

## 🔄 사후 침투 정보 수집

### 시스템 열거 (Linux)
```bash
# 시스템 정보
uname -a                      # 커널 정보
cat /etc/os-release           # OS 릴리스 정보
cat /proc/version             # 프로세서 버전
hostnamectl                   # 호스트 정보

# 사용자 정보
whoami                        # 현재 사용자
id                           # 사용자 ID 및 그룹
cat /etc/passwd              # 사용자 계정
cat /etc/group               # 그룹 정보
last                         # 로그인 기록
w                            # 현재 로그인 사용자

# 네트워크 설정
ifconfig                     # 네트워크 인터페이스 (구버전)
ip addr show                 # IP 주소 (신버전)
ip route show                # 라우팅 테이블
netstat -rn                  # 라우팅 테이블
cat /etc/resolv.conf         # DNS 설정

# 실행 중인 프로세스
ps aux                       # 모든 프로세스
ps -ef                       # 프로세스 트리
pstree                       # 프로세스 트리 시각화

# 설치된 소프트웨어
dpkg -l                      # Debian/Ubuntu 패키지
rpm -qa                      # RedHat/CentOS 패키지
which gcc                    # GCC 컴파일러 확인
which python                 # Python 확인
which perl                   # Perl 확인

# 서비스
systemctl list-units --type=service  # systemd 서비스
service --status-all                  # SysV 서비스
chkconfig --list                      # 부팅시 서비스

# 스케줄된 작업
crontab -l                   # 사용자 cron 작업
ls -la /etc/cron*            # 시스템 cron 디렉토리
cat /etc/crontab             # 시스템 crontab

# SUID/SGID 파일
find / -type f -perm -4000 -ls 2>/dev/null    # SUID 파일
find / -type f -perm -2000 -ls 2>/dev/null    # SGID 파일

# 전체 쓰기 가능한 파일
find / -type f -perm -002 -ls 2>/dev/null     # 쓰기 가능한 파일
find / -type d -perm -002 -ls 2>/dev/null     # 쓰기 가능한 디렉토리

# 최근 수정된 파일
find / -mtime -1 -ls 2>/dev/null              # 1일 내 수정
find / -atime -1 -ls 2>/dev/null              # 1일 내 접근

# 파일 권한 (capabilities)
getcap -r / 2>/dev/null
```

### 시스템 열거 (Windows)
```cmd
# 시스템 정보
systeminfo                                   # 시스템 상세 정보
wmic computersystem get Model,Manufacturer   # 하드웨어 정보
wmic bios get SMBIOSBIOSVersion             # BIOS 정보

# 사용자 정보
whoami /all                  # 현재 사용자 권한
net user                     # 로컬 사용자
net localgroup               # 로컬 그룹
net group /domain            # 도메인 그룹
query user                   # 로그인 사용자

# 네트워크 설정
ipconfig /all                # IP 설정
route print                  # 라우팅 테이블
arp -a                       # ARP 테이블
netsh interface show interface  # 네트워크 인터페이스

# 실행 중인 프로세스 및 서비스
tasklist                     # 프로세스 목록
wmic process list full       # 프로세스 상세 정보
sc query                     # 서비스 쿼리
wmic service list brief      # 서비스 목록

# 설치된 소프트웨어
wmic product get name,version         # 설치된 프로그램
dir "C:\Program Files"               # 프로그램 디렉토리
dir "C:\Program Files (x86)"         # 32비트 프로그램 디렉토리

# 스케줄된 작업
schtasks /query /fo LIST /v          # 스케줄된 작업
at                                   # AT 명령어 작업

# 레지스트리 열거
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall  # 설치된 프로그램
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run        # 사용자 시작프로그램
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run        # 시스템 시작프로그램

# 파일 시스템
dir C:\ /a                   # C 드라이브 루트
icacls C:\                   # 접근 권한
```

---

## 🤖 자동화 도구

### AutoRecon
```bash
# 설치
sudo python3 -m pip install autorecon

# 실행
autorecon <대상>              # 단일 대상
autorecon -t <대상목록.txt>   # 대상 목록 파일
autorecon --heartbeat 60 <대상>  # 60초마다 상태 보고
```

### nmapAutomator
```bash
# 복제
git clone https://github.com/21y4d/nmapAutomator.git

# 실행
./nmapAutomator.sh <대상> All     # 전체 스캔
./nmapAutomator.sh <대상> Basic   # 기본 스캔
./nmapAutomator.sh <대상> Heavy   # 무거운 스캔
```

### Legion
```bash
# 설치 및 실행
sudo apt install legion
legion
```

---

## 📝 빠른 참조 명령어

### 네트워크 발견 원라이너
```bash
# 빠른 생존 확인
nmap -sn 192.168.1.0/24 | grep -E "Nmap scan report|MAC Address"

# 빠른 포트 스캔 상위 1000개
nmap -T4 -F <대상> --open

# 빠른 종합 스캔
nmap -T4 -A -v <대상> --open

# 모든 TCP 포트 (빠름)
nmap -p- --min-rate=1000 -T4 <대상>

# 빠른 UDP 스캔
nmap -sU --top-ports 100 --open <대상>
```

### 서비스별 빠른 스캔
```bash
# 웹 서버
nmap -p 80,443,8080,8443 --script http-enum <대상>

# 데이터베이스 서비스
nmap -p 1433,3306,5432,1521 --script "*-info" <대상>

# 메일 서비스
nmap -p 25,110,143,993,995 --script "*-info" <대상>

# 파일 공유
nmap -p 21,22,139,445,2049 --script "*-enum*" <대상>

# 원격 접근
nmap -p 22,23,3389,5900 <대상>
```

### 결과 추출용 Grep 활용법
```bash
# nmap 출력에서 열린 포트 추출
grep -E "^[0-9]+/(tcp|udp)" nmap_output.txt

# 열린 포트가 있는 IP 추출
grep -B 2 "open" nmap_output.txt | grep "Nmap scan report"

# 특정 서비스 찾기
grep -i "http\|ssh\|ftp\|smtp" nmap_output.txt
```

---

## 🔧 환경 설정

### 필수 도구 설치
```bash
# 저장소 업데이트
sudo apt update && sudo apt upgrade -y

# 핵심 도구
sudo apt install -y nmap netcat-traditional dnsrecon dnsenum nbtscan onesixtyone snmp snmp-mibs-downloader smbclient rpcclient enum4linux

# 웹 열거
sudo apt install -y gobuster dirb nikto wpscan

# 추가 도구
sudo apt install -y whatweb sslscan sslyze sublist3r theHarvester

# SecLists 설치
sudo apt install seclists
# 또는 수동으로: git clone https://github.com/danielmiessler/SecLists.git

# Python 도구
pip3 install requests beautifulsoup4 dnspython
```

### 유용한 워드리스트 위치
```bash
# SecLists
/usr/share/seclists/Discovery/DNS/           # DNS 관련
/usr/share/seclists/Discovery/Web-Content/   # 웹 콘텐츠
/usr/share/seclists/Usernames/               # 사용자명
/usr/share/seclists/Passwords/               # 패스워드

# Dirb
/usr/share/dirb/wordlists/                   # Dirb 워드리스트

# 내장 워드리스트
/usr/share/wordlists/                        # 일반 워드리스트

# 사용자 정의 워드리스트 생성
cewl http://target.com > custom_wordlist.txt
```

---

## ⚠️ OSCP 시험 고려사항

### 시간 관리
1. **AutoRecon으로 시작**: 초기 열거
2. **병렬 스캔**: 여러 도구 동시 실행
3. **고가치 포트 우선**: 21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900
4. **진행상황 문서화**: 발견사항 즉시 기록

### 일반적인 포트 우선순위
```bash
# 높은 우선순위 (공격 벡터)
21    # FTP - 익명 접근, 파일 업로드
22    # SSH - 키 인증, 사용자 열거
23    # Telnet - 평문 크리덴셜
25    # SMTP - 사용자 열거
53    # DNS - 영역 전송, 서브도메인 열거
80    # HTTP - 웹 취약점
135   # RPC - Windows 열거
139   # NetBIOS - SMB 열거
443   # HTTPS - 인증서 정보, 웹 취약점
445   # SMB - 공유 열거, 널 세션
1433  # MSSQL - 데이터베이스 접근
3306  # MySQL - 데이터베이스 접근
3389  # RDP - 원격 데스크톱
5432  # PostgreSQL - 데이터베이스 접근

# 중간 우선순위
110   # POP3 - 이메일 접근
111   # RPC - 서비스 열거
143   # IMAP - 이메일 접근
161   # SNMP - 시스템 정보
993   # IMAPS - 보안 이메일
995   # POP3S - 보안 이메일
2049  # NFS - 파일 공유
5900  # VNC - 원격 데스크톱
```

### 스텔스 고려사항
```bash
# 느리지만 더 은밀함
nmap -T2 <대상>

# 탐지 회피
nmap -f <대상>                    # 패킷 단편화
nmap -D RND:10 <대상>             # 미끼 스캔
nmap --source-port 53 <대상>      # 소스 포트 스푸핑
nmap --data-length 25 <대상>      # 랜덤 데이터 길이
```

### 출력 관리
```bash
# 체계화된 출력 구조
mkdir enum_results
cd enum_results

# Nmap 모든 출력 형식
nmap -oA initial_scan <대상>

# Grep 친화적 결과
nmap -oG quick_scan.gnmap <대상>

# 결과 파싱
grep "open" *.gnmap | cut -d' ' -f2 | sort -u > live_hosts.txt
```

### 문서화 템플릿
```bash
# 열거 노트 템플릿 생성
cat > enum_notes.md << EOF
# 대상: <IP주소>

## 네트워크 정보
- OS: 
- 열린 포트: 
- 서비스: 

## 웹 애플리케이션
- 기술: 
- 디렉토리: 
- 취약점: 

## 잠재적 공격 벡터
1. 
2. 
3. 

## 발견된 크리덴셜
- 

## 메모
- 
EOF
```

---

## 📋 실전 시나리오 가이드

### 🕐 시간대별 접근 전략

#### ⏰ 첫 30분 - 빠른 정찰 단계
**목표**: 최대한 많은 정보를 빠르게 수집
```bash
# 1. 즉시 시작 (병렬 실행)
autorecon <대상> &                    # 백그라운드에서 종합 스캔
nmap -T4 -A <대상> &                  # 기본 서비스 탐지
sublist3r -d <도메인> &               # 서브도메인 발견

# 2. 웹 서비스 확인 (있다면)
whatweb http://<대상>                 # 기술 스택 빠른 확인
curl -I http://<대상>                 # HTTP 헤더 확인
gobuster dir -u http://<대상> -w /usr/share/seclists/Discovery/Web-Content/common.txt &

# 3. 일반적인 서비스 확인
enum4linux <대상>                    # SMB가 있다면
snmpwalk -c public -v1 <대상>         # SNMP가 있다면
```

**이 시점에서 확인할 것들:**
- 웹 서비스 존재 여부 (포트 80, 443, 8080 등)
- SMB 서비스 (포트 139, 445)
- SSH 서비스 (포트 22) - 버전 확인
- 데이터베이스 서비스 (포트 3306, 1433, 5432)

#### ⏰ 30분 - 1시간 - 심화 분석 단계
**목표**: 발견된 서비스 심화 분석 및 취약점 탐지
```bash
# 웹 서비스가 발견된 경우
nikto -h http://<대상> &              # 취약점 스캔
dirb http://<대상> &                  # 디렉토리 브루트포스
wpscan --url http://<대상> --enumerate p,t,u &  # WordPress라면

# SMB 서비스가 발견된 경우
smbclient -L //<대상> -N              # 널 세션 시도
smbmap -H <대상> -u guest             # 게스트 접근 시도
rpcclient -U "" -N <대상>             # RPC 널 세션

# SSH가 발견된 경우
ssh-audit <대상>                      # SSH 설정 분석
hydra -L users.txt -P passwords.txt ssh://<대상>  # 약한 크리덴셜 확인
```

#### ⏰ 1시간 - 2시간 - 공격 벡터 개발
**목표**: 구체적인 침투 경로 개발
```bash
# 웹 애플리케이션 심화
ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://<대상>/FUZZ
sqlmap -u "http://<대상>/page?id=1" --batch  # SQL 인젝션 테스트
nuclei -u http://<대상> -t cves/               # CVE 기반 스캔

# 파일 공유 서비스
showmount -e <대상>                   # NFS 마운트 확인
smbclient //<대상>/공유명              # SMB 공유 접근 시도

# 브루트포스 공격
hydra -L users.txt -P passwords.txt <서비스>://<대상>
```

### 🎯 서비스 발견별 대응 전략

#### 🌐 웹 서비스 발견 시 (포트 80, 443, 8080, 8443)
```bash
# 즉시 실행 체크리스트
1. whatweb http://<대상>               # 기술 스택 확인
2. curl http://<대상>/robots.txt      # 로봇 배제 파일
3. gobuster dir -u http://<대상> -w /usr/share/seclists/Discovery/Web-Content/common.txt
4. nikto -h http://<대상>

# 기술별 특화 전략
WordPress → wpscan --url http://<대상> --enumerate p,t,u
Joomla → joomscan -u http://<대상>
Drupal → droopescan scan drupal -u http://<대상>
Apache → 기본 페이지, 서버 상태 페이지 확인
IIS → .asp, .aspx 파일 중심 탐색
```

**⚠️ 주의사항**: 웹 서비스는 가장 일반적인 침투 경로이므로 최우선으로 분석

#### 💾 SMB/NetBIOS 발견 시 (포트 139, 445)
```bash
# 순차 실행 체크리스트
1. enum4linux -a <대상>               # 종합 정보 수집
2. smbclient -L //<대상> -N            # 널 세션 공유 확인
3. smbmap -H <대상> -u guest           # 게스트 접근
4. rpcclient -U "" -N <대상>           # RPC 정보 수집
5. nmap --script smb-vuln-* <대상>     # SMB 취약점 스캔

# 결과별 대응
널 세션 성공 → 사용자/그룹 정보 수집
공유 폴더 접근 가능 → 파일 다운로드 및 분석
EternalBlue 취약점 → 즉시 exploit 시도
```

#### 🔐 SSH 발견 시 (포트 22)
```bash
# 기본 정보 수집
ssh -V <대상>                         # 버전 확인
nmap --script ssh2-enum-algos <대상>   # 지원 알고리즘

# 공격 전략 결정
약한 버전 → 알려진 CVE 검색
사용자 열거 가능 → 사용자명 브루트포스
키 인증만 허용 → 개인키 파일 탐색
패스워드 인증 허용 → 약한 패스워드 브루트포스
```

#### 🗄️ 데이터베이스 발견 시 (포트 3306, 1433, 5432, 1521)
```bash
# MySQL (3306)
nmap --script mysql-info <대상>
mysql -h <대상> -u root -p            # 기본 계정 시도

# MSSQL (1433)  
nmap --script ms-sql-info <대상>
sqsh -S <대상> -U sa                  # SA 계정 시도

# PostgreSQL (5432)
psql -h <대상> -U postgres            # postgres 계정 시도

# Oracle (1521)
nmap --script oracle-sid-brute <대상>  # SID 브루트포스
```

### 🚧 막혔을 때의 체크리스트

#### 📝 정보 수집 단계에서 막혔을 때
```bash
# 1. 포트 범위 확장
nmap -p- <대상>                       # 전체 포트 스캔
nmap -sU --top-ports 1000 <대상>      # UDP 포트 확장

# 2. 다른 IP 범위 확인
nmap -sn 192.168.1.0/24               # 다른 네트워크 세그먼트
nmap -sn 10.10.10.0/24                # 내부 네트워크

# 3. 도메인명 기반 추가 정보
theHarvester -d <도메인> -b all        # 이메일/서브도메인
fierce -dns <도메인>                   # DNS 브루트포스

# 4. SSL 인증서 분석
openssl s_client -connect <대상>:443 | openssl x509 -text | grep DNS
```

#### 🌐 웹 애플리케이션에서 막혔을 때
```bash
# 1. 다른 워드리스트 시도
gobuster dir -u http://<대상> -w /usr/share/seclists/Discovery/Web-Content/big.txt
gobuster dir -u http://<대상> -w /usr/share/dirb/wordlists/common.txt

# 2. 파일 확장자 추가
ffuf -w wordlist.txt -u http://<대상>/FUZZ -e .php,.html,.txt,.js,.asp,.aspx

# 3. 매개변수 브루트포스
arjun -u http://<대상>/page.php

# 4. 가상 호스트 브루트포스
ffuf -w subdomains.txt -u http://<대상> -H "Host: FUZZ.<도메인>"
```

#### 🔐 인증이 필요한 서비스를 만났을 때
```bash
# 1. 기본 크리덴셜 시도
admin:admin, admin:password, root:root, administrator:administrator

# 2. 서비스별 기본 계정
MySQL: root:(빈값), root:root
MSSQL: sa:(빈값), sa:sa
PostgreSQL: postgres:postgres
Oracle: scott:tiger, sys:sys

# 3. 브루트포스 (신중하게)
hydra -L users.txt -P passwords.txt <서비스>://<대상>
```

### 🎯 정보 수집 결과별 다음 단계 가이드

#### 🟢 웹 애플리케이션 발견 → 다음 단계
```
발견 정보 → 다음 행동
─────────────────────────────
CMS 발견 → CMS별 전용 스캐너 사용
파일 업로드 → 악성 파일 업로드 시도
SQL 인젝션 → sqlmap으로 DB 덤프
XSS 발견 → 관리자 쿠키 탈취 시도
LFI/RFI → 설정 파일 읽기, 코드 실행
```

#### 🟢 시스템 서비스 발견 → 다음 단계  
```
발견 정보 → 다음 행동
─────────────────────────────
SMB 널세션 → 사용자 열거 후 패스워드 스프레이
SSH 약한 버전 → CVE 검색 및 exploit
FTP 익명 접근 → 파일 다운로드, 업로드 시도
SNMP public → 시스템 정보 수집
데이터베이스 노출 → 기본 계정 접근 시도
```

#### 🟢 크리덴셜 발견 → 다음 단계
```
크리덴셜 유형 → 활용 방법
─────────────────────────────
사용자:패스워드 → SSH, RDP, 웹 로그인 시도
해시값 → hashcat으로 크랙 시도
API 키 → API 문서 찾아서 권한 확인
데이터베이스 계정 → DB 접근 후 권한 상승
서비스 계정 → 해당 서비스 관리 패널 접근
```

### ⏰ 시간별 우선순위 변경 전략

#### 🕐 처음 2시간 (탐색 중심)
1. **자동화 도구 우선**: AutoRecon, Nmap, Gobuster 병렬 실행
2. **웹 서비스 최우선**: 80, 443, 8080, 8443 포트 집중
3. **일반적인 서비스**: SSH, SMB, FTP 기본 점검
4. **문서화**: 발견사항 즉시 기록

#### 🕑 2-4시간 (심화 분석)
1. **발견된 서비스 심화**: 각 서비스별 전용 도구 사용
2. **브루트포스 시작**: 약한 크리덴셜 탐색
3. **취약점 스캔**: Nuclei, Nikto 등 활용
4. **수동 검증**: 자동화 도구 결과 수동 확인

#### 🕒 4시간 이후 (공격 시도)
1. **직접 공격**: 발견된 취약점 직접 공격
2. **대안 경로**: 다른 서비스나 포트 확인
3. **소셜 엔지니어링**: 수집된 정보로 패스워드 추측
4. **크리에이티브 접근**: 비표준 포트, 숨겨진 서비스

### 🚨 일반적인 실수와 회피법

#### ❌ 흔한 실수들
```
실수 → 올바른 접근
─────────────────────────────
한 번에 하나씩 → 병렬로 여러 스캔 동시 실행
웹만 집중 → 모든 서비스 균형있게 확인
자동화만 의존 → 수동 검증도 병행
문서화 소홀 → 발견 즉시 기록
시간 배분 실패 → 시간별 우선순위 변경
```

#### ✅ 성공 전략
```bash
# 1. 항상 병렬 실행
command1 & command2 & command3

# 2. 결과 즉시 확인
ls -la scan_results/
tail -f autorecon_results/

# 3. 백업 계획 준비
# 주요 공격이 실패하면 다른 서비스로 전환

# 4. 시간 체크
date && echo "2시간 경과, 전략 재점검 필요"
```

### 📊 진행 상황 체크포인트

#### ✅ 30분 체크포인트
- [ ] 기본 포트 스캔 완료
- [ ] 웹 서비스 확인 완료  
- [ ] 주요 서비스 식별 완료
- [ ] AutoRecon 실행 중

#### ✅ 1시간 체크포인트  
- [ ] 모든 서비스 기본 열거 완료
- [ ] 웹 디렉토리 브루트포스 진행 중
- [ ] 취약점 스캔 시작
- [ ] 첫 번째 공격 벡터 식별

#### ✅ 2시간 체크포인트
- [ ] 심화 분석 완료
- [ ] 브루트포스 결과 확인
- [ ] exploit 시도 준비 완료
- [ ] 대안 경로 준비 완료

**🎯 핵심 원칙**: 막히면 다른 각도에서 접근. 한 곳에 너무 오래 매달리지 말 것!

---

## 🎯 고급 기법

### 인증서 분석을 통한 서브도메인 발견
```bash
# SSL 인증서에서 도메인 추출
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -text | grep -oE '[a-zA-Z0-9.-]+\.target\.com' | sort -u

# 인증서 투명성 로그
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

### 고급 SMB 열거
```bash
# 널 세션 열거
rpcclient -U "" -N <대상>
smbclient -N -L //<대상>

# 크리덴셜을 사용한 공유 열거
smbmap -H <대상> -u guest
smbmap -H <대상> -u null -p ""

# Enum4linux 종합 스캔
enum4linux -a <대상>
```

### LDAP 고급 쿼리
```bash
# 익명 바인드
ldapsearch -x -h <대상> -s base namingcontexts

# 모든 사용자 추출
ldapsearch -x -h <대상> -b "dc=example,dc=com" "(objectclass=user)" sAMAccountName

# 그룹 추출
ldapsearch -x -h <대상> -b "dc=example,dc=com" "(objectclass=group)" cn
```

이 종합적인 치트시트에는 OSCP 성공에 필요한 모든 핵심 영역이 포함되어 있으며, 시험 환경에 특화된 실용적인 예제와 시간 절약 기법이 담겨 있습니다!
