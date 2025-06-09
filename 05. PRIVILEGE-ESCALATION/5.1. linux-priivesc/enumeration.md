# Linux Privilege Escalation - Enumeration

> **OSCP 핵심**: 리눅스 쉘 획득 후 즉시 실행할 권한상승 정보 수집 명령어들

## ⚡ 즉시 실행할 명령어들

### 🔥 원라이너 최우선 명령어 (30초 안에 실행)

```bash
# 현재 사용자 및 권한 확인
id && whoami && groups

# sudo 권한 확인 (패스워드 없이)
sudo -l

# SUID 파일 찾기 (빠른 검색)
find / -type f -perm -4000 2>/dev/null

# 현재 디렉토리의 숨겨진 파일들
ls -la

# 홈 디렉토리 확인
ls -la ~/ 2>/dev/null

# 현재 프로세스 확인
ps aux | grep root
```

### 🚀 핵심 시스템 정보 (1분 안에)

```bash
# OS 버전 (커널 익스플로잇용)
uname -a && cat /etc/*release* 2>/dev/null

# 현재 사용자 상세 정보
cat /etc/passwd | grep $(whoami)

# 그룹 멤버십 상세
cat /etc/group | grep $(whoami)

# 네트워크 연결 상태
netstat -tulnp 2>/dev/null || ss -tulnp 2>/dev/null

# 환경 변수 (PATH 하이재킹용)
echo $PATH && env | grep -E "(PATH|LD_|PYTHON)"
```

## 📋 단계별 체크리스트

### Phase 1: 기본 정보 수집 (2-3분)

- [ ] **현재 사용자 확인**: `id && whoami && groups`
- [ ] **sudo 권한 확인**: `sudo -l`
- [ ] **OS/커널 버전**: `uname -a && cat /etc/*release*`
- [ ] **홈 디렉토리 탐색**: `ls -la ~/ && cat ~/.bash_history 2>/dev/null`
- [ ] **현재 디렉토리**: `pwd && ls -la`

### Phase 2: 파일 시스템 분석 (3-5분)

- [ ] **SUID/GUID 파일**: `find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null`
- [ ] **World writable 파일**: `find / -type f -perm -002 2>/dev/null`
- [ ] **사용자 소유 파일**: `find / -user $(whoami) 2>/dev/null`
- [ ] **그룹 소유 파일**: `find / -group $(id -gn) 2>/dev/null`
- [ ] **최근 수정된 파일**: `find / -type f -mmin -60 2>/dev/null`

### Phase 3: 프로세스 및 서비스 (2-3분)

- [ ] **실행 중인 프로세스**: `ps aux`
- [ ] **root 프로세스**: `ps aux | grep root`
- [ ] **네트워크 연결**: `netstat -tulnp 2>/dev/null`
- [ ] **cron jobs**: `cat /etc/crontab && ls -la /etc/cron*`
- [ ] **systemd 서비스**: `systemctl list-units --type=service --state=running 2>/dev/null`

### Phase 4: 설정 및 로그 파일 (2-3분)

- [ ] **중요 설정 파일**: `cat /etc/passwd /etc/shadow /etc/hosts 2>/dev/null`
- [ ] **SSH 설정**: `cat /etc/ssh/sshd_config 2>/dev/null`
- [ ] **웹 서버 설정**: `find /etc -name "*.conf" 2>/dev/null | head -20`
- [ ] **로그 파일**: `find /var/log -readable 2>/dev/null`
- [ ] **임시 파일들**: `ls -la /tmp /var/tmp /dev/shm 2>/dev/null`

## 🎯 발견별 즉시 실행 명령어

### 🔑 SUID 파일 발견시

```bash
# GTFOBins에서 확인할 SUID 바이너리들
find / -type f -perm -4000 2>/dev/null | grep -E "(nmap|vim|find|bash|more|less|nano|cp|mv|python|perl|ruby|tar|zip|unzip|gdb|strace|tcpdump|wireshark)"

# 각 SUID 파일의 기능 확인
ls -la $(find / -type f -perm -4000 2>/dev/null)

# 커스텀 SUID 프로그램 확인 (표준이 아닌 것들)
find / -type f -perm -4000 2>/dev/null | grep -v -E "^/(bin|sbin|usr)"
```

### 📁 쓰기 권한 발견시

```bash
# /etc/passwd 쓰기 권한 확인
ls -la /etc/passwd

# sudo 설정 파일 쓰기 권한
ls -la /etc/sudoers.d/

# cron 디렉토리 쓰기 권한
ls -la /etc/cron* /var/spool/cron* 2>/dev/null

# 시스템 바이너리 디렉토리 쓰기 권한
ls -la /bin /sbin /usr/bin /usr/sbin /usr/local/bin 2>/dev/null
```

### 🌐 네트워크 서비스 발견시

```bash
# 내부 서비스 확인 (포트 포워딩 대상)
netstat -tulnp | grep 127.0.0.1

# 현재 연결 상태
ss -tulnp 2>/dev/null | grep LISTEN

# 방화벽 규칙 확인
iptables -L 2>/dev/null || ufw status 2>/dev/null
```

### ⏰ Cron Job 발견시

```bash
# 모든 cron 관련 파일
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /var/spool/cron/crontabs/ 2>/dev/null
crontab -l 2>/dev/null

# 실행 중인 cron 프로세스
ps aux | grep cron

# cron 로그 확인
tail -f /var/log/cron* 2>/dev/null &
tail -f /var/log/syslog 2>/dev/null | grep CRON &
```

### 🔧 특정 소프트웨어 발견시

```bash
# Docker 권한 확인
groups | grep docker && docker ps 2>/dev/null

# LXD/LXC 그룹 확인
groups | grep lxd && lxc list 2>/dev/null

# MySQL/Database 접근
mysql -u root -p 2>/dev/null
find /var/lib/mysql -readable 2>/dev/null

# Web 서버 설정
find /var/www /etc/apache2 /etc/nginx -readable 2>/dev/null
```

## 🤖 자동화 도구 활용

### 🔍 LinPEAS (가장 추천)

```bash
# 다운로드 및 실행
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# 또는 wget
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh

# 결과를 파일로 저장
./linpeas.sh > linpeas_output.txt 2>&1

# 특정 모듈만 실행 (빠른 실행)
./linpeas.sh -q -o SysI,Devs,AvaSof,ProCronSrvcsTmrsSocks,Net,UsrI,SofI,IntFiles
```

### 🔎 LinEnum

```bash
# 다운로드 및 실행
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh && chmod +x LinEnum.sh && ./LinEnum.sh

# 상세 모드로 실행
./LinEnum.sh -t

# 키워드 검색과 함께
./LinEnum.sh -k password,key,secret
```

### 🎯 Linux Smart Enumeration (LSE)

```bash
# 다운로드 및 실행
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh && chmod +x lse.sh

# 레벨 1 (빠른 검사)
./lse.sh -l1

# 레벨 2 (상세 검사)
./lse.sh -l2

# 특정 섹션만
./lse.sh -s
```

### 🔧 커스텀 원라이너 스크립트

```bash
# 종합 정보 수집 스크립트 (복붙 가능)
echo "=== SYSTEM INFO ===" && uname -a && echo "=== USER INFO ===" && id && whoami && groups && echo "=== SUDO RIGHTS ===" && sudo -l 2>/dev/null && echo "=== SUID FILES ===" && find / -type f -perm -4000 2>/dev/null && echo "=== NETWORK ===" && netstat -tulnp 2>/dev/null && echo "=== PROCESSES ===" && ps aux | grep root | head -10

# 취약점 빠른 체크
find / -name "*.conf" -readable 2>/dev/null | head -20; find /var/log -readable 2>/dev/null | head -10; cat /etc/passwd | grep -E "(bash|sh)$"; cat ~/.bash_history 2>/dev/null | tail -20
```

## 👀 놓치기 쉬운 것들

### 🚨 자주 놓치는 체크포인트

```bash
# 1. 환경 변수의 PATH 하이재킹 가능성
echo $PATH | tr ":" "\n" | while read dir; do ls -la "$dir" 2>/dev/null; done

# 2. LD_PRELOAD 설정
env | grep LD_

# 3. Python 라이브러리 경로
python3 -c "import sys; print('\n'.join(sys.path))" 2>/dev/null

# 4. 숨겨진 파일들 (.* 파일들)
find /home -name ".*" -type f 2>/dev/null | head -20

# 5. /opt, /usr/local에서 커스텀 설치 확인
ls -la /opt /usr/local/bin /usr/local/sbin 2>/dev/null

# 6. 메모리에서 패스워드 찾기
strings /proc/*/environ 2>/dev/null | grep -i pass

# 7. 최근 명령어 히스토리
find /home -name ".*history" 2>/dev/null -exec cat {} \;

# 8. SSH 키 확인
find / -name "id_rsa*" -o -name "id_dsa*" -o -name "id_ecdsa*" -o -name "id_ed25519*" 2>/dev/null

# 9. 데이터베이스 파일
find / -name "*.db" -o -name "*.sql" -o -name "*.sqlite*" 2>/dev/null | head -10

# 10. 설정 백업 파일
find /etc -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*~" 2>/dev/null
```

### 🔍 고급 열거 기법

```bash
# 1. 프로세스별 열린 파일 확인
lsof -nP 2>/dev/null | grep -v "can't identify protocol"

# 2. 컴파일러 확인 (권한상승 컴파일용)
which gcc g++ make python python3 perl ruby 2>/dev/null

# 3. Capabilities 확인
getcap -r / 2>/dev/null

# 4. 마운트된 파일시스템
mount | grep -E "(ext|fat|ntfs|cifs|nfs)"

# 5. 로드된 커널 모듈
lsmod | head -20

# 6. Systemd 타이머 (cron 대신 사용되는 경우)
systemctl list-timers 2>/dev/null

# 7. 메일 스풀 확인
ls -la /var/mail/ /var/spool/mail/ 2>/dev/null

# 8. 실행 중인 Docker 컨테이너 확인
docker ps 2>/dev/null || podman ps 2>/dev/null

# 9. 최근 로그인 기록
last -10 2>/dev/null

# 10. 네트워크 인터페이스 정보
ip addr show 2>/dev/null || ifconfig 2>/dev/null
```

### ⚡ 응급상황 빠른 체크 (막혔을 때)

```bash
# 모든 것이 안될 때 마지막 시도들
echo "1. Checking for writable /etc/passwd..."; ls -la /etc/passwd
echo "2. Checking for NOPASSWD sudo..."; sudo -l 2>/dev/null | grep NOPASSWD
echo "3. Checking for docker group..."; groups | grep docker
echo "4. Checking for unusual SUID..."; find / -type f -perm -4000 2>/dev/null | grep -v -E "^/(bin|sbin|usr/(bin|sbin|libexec))"
echo "5. Checking for cron jobs..."; cat /etc/crontab 2>/dev/null
echo "6. Checking for world-writable dirs..."; find / -type d -perm -002 2>/dev/null | head -5
echo "7. Checking for readable /etc/shadow..."; ls -la /etc/shadow 2>/dev/null
echo "8. Checking for NFS exports..."; cat /etc/exports 2>/dev/null
```

## 🚨 중요 참고사항

### ⏰ 시간 관리

- **처음 5분**: 자동화 도구 (LinPEAS) 실행하면서 동시에 수동 체크
- **다음 5분**: SUID 파일과 sudo 권한 집중 분석
- **그 다음 5분**: cron job과 쓰기 가능 파일 확인
- **15분 후**: 여전히 방법이 없으면 다른 벡터나 머신 고려

### 🎯 우선순위

1. **sudo -l** (가장 빠른 승부처)
2. **SUID 바이너리** (GTFOBins 검색)
3. **Cron jobs** (스크립트 오버라이트)
4. **쓰기 가능한 /etc/passwd** (새 root 유저 추가)
5. **Docker/LXD 그룹** (컨테이너 이스케이프)

### 🔥 즉시 시도할 것들

- LinPEAS 실행과 동시에 `sudo -l` 체크
- SUID 파일 중 GTFOBins에 있는 것들 우선 확인
- `/tmp`와 `/var/tmp`에 LinPEAS 업로드 후 실행
- 히스토리 파일에서 패스워드나 중요 정보 검색
