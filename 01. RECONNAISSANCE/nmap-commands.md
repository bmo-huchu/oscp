# 🔍 NMAP COMMANDS

> **목표: nmap을 활용한 빠르고 효율적인 타겟 스캔**

## ⚡ 즉시 실행할 명령어들

### 🚀 기본 스캔 세트 (시험 시작 즉시)

```bash
# 1. 빠른 기본 스캔 (상위 1000개 포트)
nmap -sC -sV -oA initial {IP}

# 2. 전체 포트 스캔 (백그라운드)
nmap -p- -oA full-scan {IP} &

# 3. UDP 스캔 (상위 1000개)
nmap -sU --top-ports 1000 -oA udp-scan {IP} &

# 4. 취약점 스캔 (기본 스캔 완료 후)
nmap --script vuln -oA vuln-scan {IP} &
```

### ⚡ 빠른 확인용 명령어들

```bash
# 호스트 살아있는지 확인
nmap -sn {IP}

# 상위 100개 포트만 빠르게
nmap --top-ports 100 {IP}

# 특정 포트만 빠르게 확인
nmap -p 80,443,22,21,25,53,110,139,143,445,993,995,3389 {IP}

# 매우 빠른 스캔 (Aggressive timing)
nmap -T5 --min-rate 1000 {IP}
```

---

## 📋 단계별 체크리스트

### 🎯 Phase 1: 기본 발견 (5분)

- [ ] **호스트 생존 확인** `nmap -sn {IP}`
- [ ] **빠른 포트 스캔** `nmap --top-ports 100 {IP}`
- [ ] **기본 서비스 스캔 시작** `nmap -sC -sV {IP}`
- [ ] **전체 포트 스캔 백그라운드 시작** `nmap -p- {IP} &`

### 🔍 Phase 2: 상세 열거 (10분)

- [ ] **기본 스캔 결과 확인 및 분석**
- [ ] **새로 발견된 포트 상세 스캔** `nmap -sC -sV -p {PORTS} {IP}`
- [ ] **UDP 스캔 시작** `nmap -sU --top-ports 1000 {IP} &`
- [ ] **OS 탐지** `nmap -O {IP}`

### 💥 Phase 3: 취약점 스캔 (10분)

- [ ] **전체 취약점 스캔** `nmap --script vuln {IP}`
- [ ] **서비스별 NSE 스크립트** 실행
- [ ] **결과 정리 및 우선순위 결정**

---

## 🎯 상황별 대응

### 🌐 웹 서비스 발견시 (80/443/8080/8443)

```bash
# HTTP 관련 스크립트
nmap --script http-* -p {PORT} {IP}

# 웹 취약점 스크립트
nmap --script http-vuln-* -p {PORT} {IP}

# 웹 디렉토리/파일 발견
nmap --script http-enum -p {PORT} {IP}

# HTTP 메소드 확인
nmap --script http-methods -p {PORT} {IP}

# 웹서버 헤더 정보
nmap --script http-headers -p {PORT} {IP}
```

### 🗂️ SMB 서비스 발견시 (139/445)

```bash
# SMB 취약점 스캔
nmap --script smb-vuln-* -p 139,445 {IP}

# SMB 정보 수집
nmap --script smb-* -p 139,445 {IP}

# EternalBlue 체크
nmap --script smb-vuln-ms17-010 -p 445 {IP}

# SMB 공유 열거
nmap --script smb-enum-shares -p 139,445 {IP}

# SMB 사용자 열거
nmap --script smb-enum-users -p 139,445 {IP}
```

### 🐧 SSH 서비스 발견시 (22)

```bash
# SSH 버전 및 알고리즘 확인
nmap --script ssh-* -p 22 {IP}

# SSH 취약점 체크
nmap --script ssh-vuln-* -p 22 {IP}

# SSH 키 교환 확인
nmap --script ssh2-enum-algos -p 22 {IP}

# 약한 키 체크
nmap --script ssh-hostkey -p 22 {IP}
```

### 🔍 DNS 서비스 발견시 (53)

```bash
# DNS 정보 수집
nmap --script dns-* -p 53 {IP}

# DNS 영역 전송 시도
nmap --script dns-zone-transfer -p 53 {IP}

# DNS 재귀 확인
nmap --script dns-recursion -p 53 {IP}

# DNS 캐시 스누핑
nmap --script dns-cache-snoop -p 53 {IP}
```

### 📧 메일 서비스 발견시 (25/110/143/993/995)

```bash
# SMTP 스크립트
nmap --script smtp-* -p 25 {IP}

# POP3 스크립트
nmap --script pop3-* -p 110 {IP}

# IMAP 스크립트
nmap --script imap-* -p 143 {IP}

# 메일 서버 취약점
nmap --script smtp-vuln-* -p 25 {IP}
```

### 🗄️ 데이터베이스 발견시 (1433/3306/5432)

```bash
# MySQL 스캔
nmap --script mysql-* -p 3306 {IP}

# MSSQL 스캔
nmap --script ms-sql-* -p 1433 {IP}

# PostgreSQL 스캔
nmap --script pgsql-* -p 5432 {IP}

# 데이터베이스 취약점
nmap --script "*sql* and vuln" {IP}
```

### 🔧 기타 서비스별 스캔

```bash
# FTP (21)
nmap --script ftp-* -p 21 {IP}

# Telnet (23)
nmap --script telnet-* -p 23 {IP}

# SNMP (161)
nmap --script snmp-* -p 161 {IP}

# LDAP (389)
nmap --script ldap-* -p 389 {IP}

# RDP (3389)
nmap --script rdp-* -p 3389 {IP}

# VNC (5900)
nmap --script vnc-* -p 5900 {IP}
```

---

## 🚨 문제 해결

### ⏰ 스캔이 너무 느릴 때

```bash
# 타이밍 조절 (빠르게)
nmap -T4 {IP}
nmap -T5 {IP}  # 매우 빠름 (부정확할 수 있음)

# 최소 전송률 설정
nmap --min-rate 1000 {IP}
nmap --min-rate 5000 {IP}

# 포트 범위 줄이기
nmap --top-ports 100 {IP}
nmap --top-ports 50 {IP}

# 병렬 처리 늘리기
nmap --min-parallelism 100 {IP}
```

### 🔒 방화벽/IDS 회피

```bash
# 스텔스 스캔
nmap -sS {IP}  # SYN 스캔

# 패킷 분할
nmap -f {IP}   # 작은 패킷으로 분할
nmap -ff {IP}  # 더 작게 분할

# 디코이 사용
nmap -D RND:10 {IP}  # 랜덤 디코이 10개
nmap -D 192.168.1.1,192.168.1.2,ME {IP}

# 소스 포트 위조
nmap --source-port 53 {IP}
nmap --source-port 80 {IP}

# 타이밍 조절 (느리게)
nmap -T1 {IP}  # 매우 느림
nmap -T2 {IP}  # 느림
```

### 🚫 포트가 filtered/closed일 때

```bash
# 다른 스캔 기법 시도
nmap -sA {IP}  # ACK 스캔
nmap -sF {IP}  # FIN 스캔
nmap -sN {IP}  # NULL 스캔
nmap -sX {IP}  # Xmas 스캔

# UDP 스캔
nmap -sU {IP}

# ICMP 스캔
nmap -PE {IP}  # ICMP Echo
nmap -PP {IP}  # ICMP Timestamp
nmap -PM {IP}  # ICMP Netmask
```

### 🔍 정보가 부족할 때

```bash
# 더 많은 NSE 스크립트
nmap --script "default or safe" {IP}
nmap --script "not intrusive" {IP}
nmap --script discovery {IP}

# 배너 그래빙
nmap --script banner {IP}

# 서비스 버전 강제 탐지
nmap -sV --version-intensity 9 {IP}

# OS 탐지 강화
nmap -O --osscan-guess {IP}
```

### 📱 특정 서비스 깊이 스캔

```bash
# HTTP 심화 스캔
nmap --script "http-* and not dos" {IP}

# SMB 심화 스캔
nmap --script "smb-* and not dos" -p 139,445 {IP}

# 모든 안전한 스크립트
nmap --script "default or safe or discovery and not intrusive" {IP}
```

---

## 🎯 효율적인 스캔 전략

### 🚀 빠른 발견 단계

```bash
# 1. 생존 확인
nmap -sn {IP}/24

# 2. 빠른 포트 스캔
nmap --top-ports 20 {IP}

# 3. 기본 서비스 확인
nmap -sV --top-ports 100 {IP}
```

### 🔍 상세 분석 단계

```bash
# 1. 전체 포트 스캔
nmap -p- {IP}

# 2. 발견된 포트 상세 스캔
nmap -sC -sV -p {DISCOVERED_PORTS} {IP}

# 3. 취약점 스캔
nmap --script vuln -p {DISCOVERED_PORTS} {IP}
```

### 💥 공격 준비 단계

```bash
# 1. 서비스별 전문 스크립트
nmap --script "http-*" -p 80,443 {IP}
nmap --script "smb-*" -p 139,445 {IP}

# 2. 인증 우회 시도
nmap --script "auth" {IP}

# 3. 브루트포스 가능성 확인
nmap --script "*brute*" {IP}
```

---

## 📊 출력 형식 옵션

### 📁 출력 저장

```bash
# 모든 형식으로 저장
nmap -oA scan-results {IP}

# 특정 형식으로 저장
nmap -oN normal.txt {IP}    # Normal 출력
nmap -oX xml.xml {IP}       # XML 출력
nmap -oG grep.txt {IP}      # Grep 가능한 출력

# 상세 로그
nmap -v -oA verbose-scan {IP}
nmap -vv -oA very-verbose {IP}
```

### 📋 유용한 조합 명령어

```bash
# 완전한 스캔 세트
nmap -sC -sV -O --script vuln -oA complete-scan {IP}

# 빠른 웹 서비스 스캔
nmap -p 80,443,8080,8443 --script http-enum,http-vuln-* {IP}

# SMB 완전 스캔
nmap -p 139,445 --script smb-vuln-*,smb-enum-* {IP}

# 서비스 발견 + 취약점 스캔
nmap -sV --script "version,vuln" {IP}
```

---

## ⏱️ 시간 효율성 팁

**15분 내에 완료해야 할 것들:**

- [ ] 기본 포트 스캔 (`-sC -sV`)
- [ ] 전체 포트 스캔 시작 (`-p-` 백그라운드)
- [ ] 주요 서비스 NSE 스크립트 실행

**30분 내에 완료해야 할 것들:**

- [ ] 모든 기본 스캔 완료
- [ ] 취약점 스캔 실행
- [ ] 다음 공격 단계 결정

**다음 단계**: 스캔 결과에 따라 `PORT-ATTACKS/` 해당 파일로 이동!
