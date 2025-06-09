# 🌐 DNS ATTACKS (Port 53)

> **목표: DNS 서비스 발견 후 15-20분 내에 도메인 정보 및 네트워크 구조 완전 매핑**

## ⚡ 즉시 실행할 명령어들

### 🚀 DNS 발견 즉시 실행

```bash
# 1. DNS 서버 기본 정보 확인
nmap -sU -sV -p 53 {IP}
nmap -sT -sV -p 53 {IP}
dig @{IP} version.bind chaos txt

# 2. 역방향 DNS 조회
dig @{IP} -x {IP}
nslookup {IP} {IP}

# 3. 기본 레코드 조회 (도메인이 있는 경우)
dig @{IP} {DOMAIN}
dig @{IP} {DOMAIN} ANY
dig @{IP} {DOMAIN} MX
dig @{IP} {DOMAIN} NS
dig @{IP} {DOMAIN} TXT

# 4. Zone Transfer 시도 (가장 중요!)
dig @{IP} {DOMAIN} AXFR
dig @{IP} {DOMAIN} IXFR

# 5. 서브도메인 스캔 시작 (백그라운드)
gobuster dns -d {DOMAIN} -r {IP} -w /usr/share/wordlists/subdomains-top1million-5000.txt &
```

### ⚡ 도메인이 없는 경우 (IP만 있을 때)

```bash
# 역방향 DNS로 도메인 찾기
dig @{IP} -x {IP}
nslookup {IP} {IP}

# 일반적인 도메인명 시도
dig @{IP} localhost
dig @{IP} example.com
dig @{IP} test.com
dig @{IP} {IP}.nip.io

# DNS 서버 정보 수집
nmap --script dns-* -p 53 {IP}
```

---

## 📋 단계별 체크리스트

### 🎯 Phase 1: 발견 및 기본 정보 수집 (5분)

- [ ] **DNS 포트 확인** `nmap -sU -p 53 {IP}`
- [ ] **DNS 서버 버전 확인** `dig @{IP} version.bind chaos txt`
- [ ] **역방향 DNS 조회** `dig @{IP} -x {IP}`
- [ ] **기본 도메인 정보 확인**
- [ ] **재귀 쿼리 가능성 확인** `dig @{IP} google.com`

### 🔍 Phase 2: 도메인 정보 수집 (5분)

- [ ] **모든 DNS 레코드 타입 확인** `dig @{IP} {DOMAIN} ANY`
- [ ] **MX, NS, TXT 레코드 확인**
- [ ] **SOA 레코드로 주 DNS 서버 확인**
- [ ] **CNAME 레코드 확인**
- [ ] **Zone Transfer 시도** `dig @{IP} {DOMAIN} AXFR`

### 🌐 Phase 3: 서브도메인 및 확장 열거 (8분)

- [ ] **자동화된 서브도메인 스캔** `gobuster dns, dnsrecon`
- [ ] **일반적인 서브도메인 수동 확인**
- [ ] **와일드카드 DNS 확인**
- [ ] **IPv6 레코드 확인** (AAAA)
- [ ] **추가 네임서버 확인**

### 📊 Phase 4: 분석 및 다음 단계 (2분)

- [ ] **발견된 호스트/서비스 정리**
- [ ] **새로운 공격 표면 식별**
- [ ] **내부 네트워크 구조 파악**
- [ ] **다음 공격 우선순위 결정**

---

## 🎯 상황별 대응

### 🏆 Zone Transfer 성공시

```bash
# AXFR (전체 영역 전송)
dig @{IP} {DOMAIN} AXFR
dig @{IP} {DOMAIN} AXFR | grep -E "^[a-zA-Z0-9]" | sort

# IXFR (증분 영역 전송) 시도
dig @{IP} {DOMAIN} IXFR

# 모든 발견된 도메인에 대해 추가 정보 수집
for subdomain in $(dig @{IP} {DOMAIN} AXFR | grep -E "^[a-zA-Z0-9]" | awk '{print $1}'); do
    echo "=== $subdomain ==="
    dig @{IP} $subdomain A
    dig @{IP} $subdomain AAAA
    dig @{IP} $subdomain CNAME
done

# 발견된 IP 주소들 nmap 스캔
dig @{IP} {DOMAIN} AXFR | grep -E "IN\s+A\s+" | awk '{print $5}' | sort -u > discovered_ips.txt
nmap -sn -iL discovered_ips.txt
```

### 🔍 서브도메인 열거 (도메인이 있는 경우)

```bash
# Gobuster를 이용한 DNS 브루트포스
gobuster dns -d {DOMAIN} -r {IP} -w /usr/share/wordlists/subdomains-top1million-5000.txt
gobuster dns -d {DOMAIN} -r {IP} -w /usr/share/wordlists/subdomains-top1million-20000.txt

# dnsrecon을 이용한 포괄적 DNS 열거
dnsrecon -d {DOMAIN} -n {IP}
dnsrecon -d {DOMAIN} -n {IP} -t axfr
dnsrecon -d {DOMAIN} -n {IP} -t brt -D /usr/share/wordlists/subdomains-top1million-5000.txt

# dnsenum을 이용한 DNS 열거
dnsenum --dnsserver {IP} --enum {DOMAIN}

# fierce를 이용한 서브도메인 스캔
fierce -dns {DOMAIN} -dnsserver {IP}

# 수동 서브도메인 확인
dig @{IP} www.{DOMAIN}
dig @{IP} mail.{DOMAIN}
dig @{IP} ftp.{DOMAIN}
dig @{IP} admin.{DOMAIN}
dig @{IP} test.{DOMAIN}
dig @{IP} dev.{DOMAIN}
dig @{IP} staging.{DOMAIN}
dig @{IP} api.{DOMAIN}
dig @{IP} portal.{DOMAIN}
dig @{IP} vpn.{DOMAIN}
```

### 📋 레코드 타입별 정보 수집

```bash
# A 레코드 (IPv4 주소)
dig @{IP} {DOMAIN} A
dig @{IP} www.{DOMAIN} A

# AAAA 레코드 (IPv6 주소)
dig @{IP} {DOMAIN} AAAA
dig @{IP} www.{DOMAIN} AAAA

# MX 레코드 (메일 서버)
dig @{IP} {DOMAIN} MX
# 발견된 메일 서버들에 대해 추가 조사

# NS 레코드 (네임서버)
dig @{IP} {DOMAIN} NS
# 다른 네임서버들도 확인

# TXT 레코드 (중요한 정보 포함 가능)
dig @{IP} {DOMAIN} TXT
# SPF, DKIM, DMARC 레코드 확인

# CNAME 레코드
dig @{IP} www.{DOMAIN} CNAME

# SOA 레코드 (도메인 관리 정보)
dig @{IP} {DOMAIN} SOA

# PTR 레코드 (역방향 조회)
dig @{IP} -x {TARGET_IP}

# SRV 레코드 (서비스 정보)
dig @{IP} _http._tcp.{DOMAIN} SRV
dig @{IP} _https._tcp.{DOMAIN} SRV
dig @{IP} _ftp._tcp.{DOMAIN} SRV
dig @{IP} _ssh._tcp.{DOMAIN} SRV
```

### 🌍 와일드카드 DNS 확인

```bash
# 와일드카드 DNS 테스트
dig @{IP} nonexistent123456.{DOMAIN}
dig @{IP} random-string-$(date +%s).{DOMAIN}

# 와일드카드가 있는 경우 실제 서브도메인과 구분
dig @{IP} www.{DOMAIN}
dig @{IP} mail.{DOMAIN}
dig @{IP} thisshouldreallynotexist12345.{DOMAIN}

# 와일드카드 IP 확인
nslookup nonexistent.{DOMAIN} {IP}
```

### 🔄 재귀 쿼리 테스트

```bash
# 재귀 쿼리 가능 여부 확인
dig @{IP} google.com
dig @{IP} microsoft.com
dig @{IP} github.com

# DNS 증폭 공격 가능성 확인
dig @{IP} . NS
dig @{IP} . ANY

# 캐시 포이즈닝 가능성 (고급)
# 주의: 실제 공격은 OSCP 시험에서 금지
```

---

## 🚨 문제 해결

### 🚫 DNS 응답이 없을 때

```bash
# UDP와 TCP 모두 시도
dig @{IP} {DOMAIN}          # UDP (기본)
dig @{IP} {DOMAIN} +tcp     # TCP 강제

# 다른 DNS 포트 확인
nmap -sU -p 53,5353 {IP}
nmap -sT -p 53,5353 {IP}

# 방화벽 우회 시도
dig @{IP} {DOMAIN} +short
dig @{IP} {DOMAIN} +trace
```

### 🔒 Zone Transfer 실패시

```bash
# 다른 네임서버들 시도
dig {DOMAIN} NS
# 발견된 각 NS에 대해 Zone Transfer 시도
dig @ns1.{DOMAIN} {DOMAIN} AXFR
dig @ns2.{DOMAIN} {DOMAIN} AXFR

# TCP로 Zone Transfer 시도
dig @{IP} {DOMAIN} AXFR +tcp

# 다른 도구로 시도
dnsrecon -d {DOMAIN} -n {IP} -t axfr
host -l {DOMAIN} {IP}
```

### 🌐 서브도메인 스캔 결과가 없을 때

```bash
# 더 작은 워드리스트로 시도
gobuster dns -d {DOMAIN} -r {IP} -w /usr/share/wordlists/subdomains-top1million-110.txt

# 다른 도구들 시도
sublist3r -d {DOMAIN}
amass enum -d {DOMAIN}

# 수동으로 일반적인 서브도메인 확인
for sub in www mail ftp admin test dev staging api portal vpn blog shop; do
    dig @{IP} $sub.{DOMAIN} | grep -E "IN\s+A\s+"
done

# 숫자 기반 서브도메인 시도
for i in {1..10}; do
    dig @{IP} $i.{DOMAIN}
    dig @{IP} web$i.{DOMAIN}
    dig @{IP} server$i.{DOMAIN}
done
```

### 🔍 도메인 정보가 부족할 때

```bash
# 역방향 DNS에서 도메인 발견 시도
for i in {1..254}; do
    dig @{IP} -x 192.168.1.$i +short
    dig @{IP} -x 10.0.0.$i +short
done

# 네트워크 범위로 역방향 조회
dig @{IP} -x {NETWORK}.1
dig @{IP} -x {NETWORK}.254

# whois 정보와 연계
whois {IP}
whois {DOMAIN}
```

### 🐌 DNS 응답이 느릴 때

```bash
# 타임아웃 조정
dig @{IP} {DOMAIN} +time=5 +tries=3

# 병렬 처리
#!/bin/bash
subdomains="www mail ftp admin test dev"
for sub in $subdomains; do
    dig @{IP} $sub.{DOMAIN} &
done
wait

# 더 빠른 도구 사용
massdns -r resolvers.txt -t A -o S subdomains.txt
```

---

## 🔗 DNS 정보 활용

### 🌐 웹 서비스 연계

```bash
# 발견된 서브도메인들의 웹 서비스 확인
for subdomain in $(gobuster dns -d {DOMAIN} -r {IP} -w wordlist.txt -q | cut -d' ' -f2); do
    echo "Checking $subdomain"
    curl -I http://$subdomain
    curl -I https://$subdomain
done

# Virtual host 스캔
gobuster vhost -u http://{IP} -w /usr/share/wordlists/subdomains-top1million-5000.txt
```

### 📧 메일 서버 연계

```bash
# MX 레코드에서 발견된 메일 서버 공격
dig @{IP} {DOMAIN} MX | grep "MX" | awk '{print $6}' > mail_servers.txt

# 각 메일 서버에 대해 포트 스캔
for mx in $(cat mail_servers.txt); do
    nmap -p 25,110,143,465,587,993,995 $mx
done
```

### 🔐 내부 네트워크 매핑

```bash
# 내부 IP 범위 추정
dig @{IP} {DOMAIN} AXFR | grep -E "IN\s+A\s+" | awk '{print $5}' | sort -u

# 발견된 IP들의 네트워크 범위 확인
for ip in $(dig @{IP} {DOMAIN} AXFR | grep -E "IN\s+A\s+" | awk '{print $5}'); do
    echo "Network for $ip:"
    ipcalc $ip/24
done
```

### 📊 취약점 정보 수집

```bash
# TXT 레코드에서 보안 정책 확인
dig @{IP} {DOMAIN} TXT | grep -i "spf\|dkim\|dmarc"

# 서비스 레코드로 서비스 포트 확인
dig @{IP} _sip._tcp.{DOMAIN} SRV
dig @{IP} _xmpp-server._tcp.{DOMAIN} SRV
dig @{IP} _ldap._tcp.{DOMAIN} SRV
```

---

## 🛠️ 고급 DNS 기법

### 🔍 DNS 캐시 스누핑

```bash
# 캐시된 레코드 확인
dig @{IP} google.com +norecurse
dig @{IP} facebook.com +norecurse
dig @{IP} microsoft.com +norecurse

# 인기 사이트들 확인
for site in google.com facebook.com twitter.com github.com; do
    echo "Checking cache for $site"
    dig @{IP} $site +norecurse +short
done
```

### 🌐 DNS 터널링 감지

```bash
# 긴 TXT 레코드 확인 (터널링 신호)
dig @{IP} {DOMAIN} TXT | grep -E ".{100,}"

# 비정상적인 서브도메인 패턴 확인
dig @{IP} $(openssl rand -hex 20).{DOMAIN}
```

### 📋 종합적인 DNS 정보 수집 스크립트

```bash
#!/bin/bash
DOMAIN=$1
DNS_SERVER=$2

echo "=== DNS Comprehensive Scan for $DOMAIN ==="

# Basic information
echo "[+] Basic DNS Info:"
dig @$DNS_SERVER $DOMAIN ANY +short

# Zone transfer attempt
echo "[+] Zone Transfer Attempt:"
dig @$DNS_SERVER $DOMAIN AXFR

# Subdomain enumeration
echo "[+] Subdomain Enumeration:"
gobuster dns -d $DOMAIN -r $DNS_SERVER -w /usr/share/wordlists/subdomains-top1million-110.txt -q

# Reverse DNS
echo "[+] Reverse DNS:"
dig @$DNS_SERVER -x $DNS_SERVER

# Check for wildcard
echo "[+] Wildcard Check:"
dig @$DNS_SERVER nonexistent12345.$DOMAIN

echo "=== Scan Complete ==="
```

---

## ⏱️ 시간 관리 가이드

### 🎯 5분 안에 완료할 것들

- [ ] DNS 서버 기본 정보 수집
- [ ] Zone Transfer 시도
- [ ] 역방향 DNS 조회
- [ ] 기본 레코드 타입 확인

### 🔍 15분 안에 완료할 것들

- [ ] 서브도메인 스캔 시작 및 진행
- [ ] 모든 DNS 레코드 타입 확인
- [ ] 재귀 쿼리 및 캐시 확인
- [ ] 발견된 호스트들의 기본 스캔

### 💥 20분 후 판단 기준

**성공 기준:**

- [ ] Zone Transfer 성공 또는 서브도메인 다수 발견
- [ ] 새로운 호스트/서비스 발견
- [ ] 내부 네트워크 구조 파악
- [ ] 추가 공격 표면 식별

**실패시 다음 단계:**

- [ ] 수집한 최소한의 정보라도 다른 공격에 활용
- [ ] 역방향 DNS로 발견한 정보 활용
- [ ] 다른 포트/서비스로 이동
- [ ] DNS 정보를 백그라운드로 계속 수집

**다음 단계**:

- 새로운 호스트 발견시 해당 호스트 스캔
- 웹 서비스 발견시 `PORT-ATTACKS/80-443-web.md`로
- 메일 서버 발견시 `PORT-ATTACKS/25-smtp.md`로
- 실패시 다른 `PORT-ATTACKS/` 파일로 이동
