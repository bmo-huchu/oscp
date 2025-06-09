# 🔍 RECONNAISSANCE CHECKLIST

> **목표: 30-45분 내에 타겟의 공격 표면 완전히 매핑**

## ⚡ 즉시 실행할 명령어들

### 🚀 시험 시작 즉시 (병렬 실행)

```bash
# 1. 기본 포트 스캔 (빠른 확인)
nmap -sC -sV -oA initial {IP}

# 2. 전체 포트 스캔 (백그라운드)
nmap -p- -oA full-scan {IP} &

# 3. UDP 스캔 (상위 1000개 포트)
nmap -sU --top-ports 1000 -oA udp-scan {IP} &

# 4. 웹 디렉토리 스캔 (80 포트 열려있으면)
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster-80.txt &

# 5. 웹 디렉토리 스캔 (443 포트 열려있으면)
gobuster dir -u https://{IP} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -o gobuster-443.txt &
```

---

## 📋 단계별 체크리스트

### 📊 Phase 1: 기본 스캔 (10분)

- [ ] **nmap 기본 스캔 완료** `nmap -sC -sV -oA initial {IP}`
- [ ] **결과 분석 및 노트 정리**
- [ ] **열린 포트 목록 작성**
- [ ] **서비스 버전 확인**
- [ ] **다음 단계 우선순위 결정**

### 🔍 Phase 2: 상세 열거 (15분)

- [ ] **전체 포트 스캔 결과 확인** `nmap -p- {IP}`
- [ ] **새로 발견된 포트 재스캔** `nmap -sC -sV -p {PORT} {IP}`
- [ ] **UDP 스캔 결과 확인** (특히 161 SNMP, 53 DNS)
- [ ] **운영체제 감지** `nmap -O {IP}`
- [ ] **NSE 스크립트 실행** `nmap --script vuln {IP}`

### 🌐 Phase 3: 웹 서비스 열거 (10분)

- [ ] **웹 서비스 기본 확인** `curl -I http://{IP}`
- [ ] **robots.txt 확인** `curl http://{IP}/robots.txt`
- [ ] **디렉토리 스캔 결과 확인** (gobuster)
- [ ] **웹 기술 스택 확인** `whatweb {IP}`
- [ ] **SSL 인증서 정보** `openssl s_client -connect {IP}:443`

### 📝 Phase 4: 정보 정리 (5분)

- [ ] **공격 벡터 우선순위 작성**
- [ ] **다음 공격 단계 계획**
- [ ] **중요 정보 하이라이트**
- [ ] **시간 체크 및 조정**

---

## 🎯 상황별 대응

### 🌐 웹 서비스 발견시 (80/443/8080/8443)

```bash
# 즉시 실행
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,asp,aspx -t 50
nikto -h http://{IP} -o nikto-scan.txt
whatweb {IP}

# 서브도메인 스캔 (도메인이 있는 경우)
gobuster vhost -u {DOMAIN} -w /usr/share/wordlists/subdomains-top1million-5000.txt

# 특정 확장자 스캔
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,asp,aspx,jsp,html
```

### 🗂️ SMB 서비스 발견시 (139/445)

```bash
# 즉시 실행
smbclient -L //{IP} -N
smbmap -H {IP}
enum4linux -a {IP}
nmap --script smb-vuln-* {IP}

# 공유 폴더 확인
smbclient //{IP}/SHARENAME -N
```

### 🐧 SSH 서비스 발견시 (22)

```bash
# 버전 확인
nmap -sV -p 22 {IP}
ssh {IP} -o PreferredAuthentications=none

# 사용자 열거 (OpenSSH < 7.7)
python3 /usr/share/nmap/scripts/ssh-enum-users.py --userList /usr/share/wordlists/metasploit/unix_users.txt {IP}
```

### 🔍 DNS 서비스 발견시 (53)

```bash
# DNS 정보 수집
nslookup {IP}
dig axfr @{IP} {DOMAIN}
dnsrecon -d {DOMAIN} -t axfr
dnsenum {DOMAIN}

# DNS 브루트포스
gobuster dns -d {DOMAIN} -w /usr/share/wordlists/subdomains-top1million-5000.txt
```

### 📧 메일 서비스 발견시 (25/110/143/993/995)

```bash
# 서비스 확인
nmap -sV -p {PORT} {IP}
telnet {IP} {PORT}

# 사용자 열거
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {IP}
```

### 🗄️ 데이터베이스 발견시 (1433/3306/5432)

```bash
# MySQL (3306)
nmap --script mysql-* {IP}
mysql -h {IP} -u root -p

# MSSQL (1433)
nmap --script ms-sql-* {IP}
sqsh -S {IP} -U sa

# PostgreSQL (5432)
nmap --script pgsql-* {IP}
psql -h {IP} -U postgres
```

---

## 🚨 문제 해결

### ⏰ 스캔이 너무 느릴 때

```bash
# 빠른 스캔으로 전환
nmap -T4 --min-rate 1000 {IP}
nmap --top-ports 1000 {IP}

# 병렬 처리 증가
gobuster dir -u http://{IP} -w wordlist -t 100
```

### 🔒 방화벽/필터링 감지시

```bash
# 스텔스 스캔
nmap -sS -f {IP}
nmap -D RND:10 {IP}

# 다른 스캔 기법
nmap -sA {IP}  # ACK 스캔
nmap -sF {IP}  # FIN 스캔
nmap -sN {IP}  # NULL 스캔
```

### 🚫 모든 포트가 closed/filtered일 때

```bash
# ICMP 확인
ping {IP}
nmap -PE {IP}

# 다른 프로토콜 시도
nmap -sU {IP}
nmap -sO {IP}

# 특정 포트 깊이 스캔
nmap -p 80,443,22,21,25,53,110,143,993,995 -A {IP}
```

### 🌐 웹 스캔 결과가 없을 때

```bash
# 다른 워드리스트 시도
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt

# 다른 확장자 시도
gobuster dir -u http://{IP} -w wordlist -x txt,bak,old,~

# 다른 도구 사용
dirb http://{IP}
dirsearch -u http://{IP}
```

### 🔍 정보가 부족할 때

```bash
# 배너 그래빙
nc -nv {IP} {PORT}
telnet {IP} {PORT}

# 서비스별 상세 스캔
nmap --script "default or safe or intrusive" {IP}

# Google dorking (도메인이 있는 경우)
site:{DOMAIN} filetype:pdf
site:{DOMAIN} inurl:admin
```

---

## ⏱️ 시간 관리 체크포인트

### 15분 경과시

- [ ] 기본 nmap 스캔 완료되었나?
- [ ] 웹 서비스 있으면 gobuster 시작했나?
- [ ] 명확한 공격 벡터 1개 이상 식별되었나?

### 30분 경과시

- [ ] 전체 포트 스캔 완료되었나?
- [ ] 모든 서비스 열거 시작했나?
- [ ] 다음 공격 단계 계획 수립되었나?

### 45분 경과시

- [ ] 모든 기본 스캔 완료되었나?
- [ ] 우선순위 공격 벡터 결정되었나?
- [ ] **정찰 단계 종료하고 공격 단계로 전환**

---

## 🎯 완료 기준

정찰 단계는 다음 조건이 만족되면 완료:

- [ ] 모든 열린 포트와 서비스 식별 완료
- [ ] 각 서비스별 기본 정보 수집 완료
- [ ] 공격 가능한 벡터 우선순위 리스트 작성 완료
- [ ] 다음 단계에서 사용할 PORT-ATTACKS 파일 식별 완료

**다음 단계**: 가장 유망한 서비스부터 `PORT-ATTACKS/` 해당 파일로 이동!
