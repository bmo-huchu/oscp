# Shell Upgrade - OSCP 공격 가이드

> **목표: 기본 쉘을 안정적이고 기능이 풍부한 TTY 쉘로 업그레이드**

## ⚡ 기본 페이로드들 (즉시 복사-붙여넣기)

### 🐍 Python TTY 업그레이드

```bash
# Python 2/3 자동 감지 TTY 업그레이드
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 완전한 TTY 업그레이드 (3단계)
# 1단계: Python TTY 생성
python -c 'import pty; pty.spawn("/bin/bash")'
# 2단계: 백그라운드로 전환 후 터미널 설정
# Ctrl+Z 누르기
stty raw -echo && fg
# 3단계: 터미널 환경 설정
export TERM=xterm
export SHELL=/bin/bash
stty rows 24 columns 80

# 원라이너 완전 업그레이드
python -c 'import pty; pty.spawn("/bin/bash")' && stty raw -echo && fg

# Python이 없을 때 다른 방법들
script -qc /bin/bash /dev/null
script /dev/null
/usr/bin/script -qc /bin/bash /dev/null

# Expect로 TTY 생성
expect -c 'spawn /bin/bash; interact'

# Socat으로 완전한 TTY
socat file:`tty`,raw,echo=0 tcp-listen:4444

# SSH-like TTY (openssh-client 설치된 경우)
ssh-keygen -f /tmp/key -N ''
cat /tmp/key.pub >> ~/.ssh/authorized_keys
ssh -i /tmp/key user@localhost
```

### 🔧 즉시 쉘 안정화

```bash
# 기본 환경 변수 설정
export TERM=xterm-256color
export SHELL=/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# 터미널 크기 설정
stty rows 50 columns 200

# 히스토리 활성화
export HISTFILE=~/.bash_history
export HISTSIZE=1000
export HISTFILESIZE=2000

# Bash 기능 활성화
set -o vi  # vi 모드
set -o emacs  # emacs 모드 (기본)

# 색상 활성화
export LS_COLORS='di=1;34:ln=1;36:so=1;35:pi=1;33:ex=1;32:bd=1;33:cd=1;33:su=1;31:sg=1;31:tw=1;34:ow=1;34:'
alias ls='ls --color=auto'
alias grep='grep --color=auto'

# 프롬프트 개선
export PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '

# 자동완성 활성화 (bash-completion 있는 경우)
if [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
fi
```

### 🎮 신호 처리 개선

```bash
# Ctrl+C, Ctrl+Z 정상 작동하게 설정
stty intr ^C
stty susp ^Z
stty quit ^\

# 모든 제어 문자 복원
stty sane

# raw 모드에서 복원
stty raw -echo
stty cooked echo

# 터미널 완전 초기화
reset
clear

# 터미널 정보 확인
stty -a
tty
echo $TERM
```

## 🎯 상황별 페이로드

### 🚫 Python이 없는 환경

```bash
# Perl로 TTY 생성
perl -e 'exec "/bin/bash"'
perl -e 'use POSIX qw(setsid); POSIX::setsid(); exec "/bin/bash"'

# Ruby로 TTY 생성
ruby -e 'exec "/bin/bash"'
ruby -e 'Process.setsid; exec "/bin/bash"'

# Lua로 TTY 생성
lua -e "os.execute('/bin/bash')"

# AWK로 TTY 생성
awk 'BEGIN {system("/bin/bash")}'

# Find를 이용한 TTY
find / -name "bash" -exec {} \; 2>/dev/null
find . -exec /bin/bash \; -quit

# Vim/Vi를 통한 쉘
vi
# :!/bin/bash
# :shell

# Less/More를 통한 쉘
less /etc/passwd
# !/bin/bash

# Node.js로 TTY 생성
node -e "require('child_process').spawn('/bin/bash', {stdio: [0, 1, 2]});"

# PHP로 TTY 생성
php -r "system('/bin/bash');"
```

### 🪟 Windows 쉘 업그레이드

```powershell
# PowerShell ISE 실행 (GUI 환경)
powershell_ise

# Windows Terminal 실행
wt.exe

# ConEmu 실행 (설치된 경우)
ConEmu64.exe

# PowerShell 색상 활성화
Set-PSReadlineOption -Colors @{
    "Command" = [ConsoleColor]::Yellow
    "Parameter" = [ConsoleColor]::Green
    "String" = [ConsoleColor]::Cyan
}

# PowerShell 프롬프트 개선
function prompt {
    $currentPath = (Get-Location).Path
    $userName = [Environment]::UserName
    $computerName = [Environment]::MachineName
    Write-Host "$userName@$computerName" -ForegroundColor Green -NoNewline
    Write-Host ":" -NoNewline
    Write-Host "$currentPath" -ForegroundColor Blue -NoNewline
    Write-Host "$ " -NoNewline
    return " "
}

# CMD 프롬프트 개선
prompt $P$_$T$G
color 0A

# PowerShell 히스토리 설정
Set-PSReadlineOption -HistoryNoDuplicates:$true
Set-PSReadlineOption -MaximumHistoryCount 1000

# PowerShell 자동완성 개선
Set-PSReadlineKeyHandler -Key Tab -Function Complete
Set-PSReadlineKeyHandler -Key Ctrl+d -Function DeleteChar
```

### 🔌 네트워크 제한 환경

```bash
# 로컬 TTY 업그레이드 (네트워크 없이)
script -qc /bin/bash /dev/null

# 파일 기반 TTY
mkfifo /tmp/tty
cat /tmp/tty | /bin/bash 2>&1 | tee /tmp/tty

# Named Pipe를 이용한 인터랙티브 쉘
mkfifo /tmp/input /tmp/output
cat /tmp/input | /bin/bash > /tmp/output 2>&1 &

# 프로세스 치환을 이용한 방법
exec 5<>/dev/tcp/127.0.0.1/22  # SSH 포트로 로컬 연결
cat <&5 | while read line; do $line 2>&5 >&5; done

# Screen/Tmux 세션 생성 (있는 경우)
screen -S upgrade /bin/bash
tmux new-session -d -s upgrade '/bin/bash'
tmux attach-session -t upgrade
```

### 🔒 제한된 rbash 환경

```bash
# rbash 탈출 방법들
cd /tmp && /bin/bash
export PATH=/bin:/usr/bin:$PATH && /bin/bash

# vi를 통한 탈출
vi
:set shell=/bin/bash
:shell

# Python을 통한 PATH 우회
python -c "import os; os.system('/bin/bash')"

# Perl을 통한 PATH 우회
perl -e 'exec "/bin/bash"'

# AWK를 통한 우회
awk 'BEGIN {system("/bin/bash")}'

# Find를 통한 우회
find / -name bash -exec {} \; 2>/dev/null

# 환경 변수 조작
export BASH_CMDS[a]=/bin/bash; a

# SSH를 통한 우회 (SSH 접근 가능한 경우)
ssh localhost -t /bin/bash

# 함수 정의를 통한 우회
function ls() { /bin/bash; }; ls
```

### 📊 쉘 기능 테스트

```bash
# 현재 쉘 정보 확인
echo $SHELL
echo $0
ps -p $$

# TTY 여부 확인
tty
test -t 0 && echo "TTY" || echo "No TTY"

# 터미널 기능 테스트
echo -e "\033[31mRed Text\033[0m"  # 색상 지원
echo -e "\033[2J\033[H"            # 화면 지우기
echo -e "\033[?25l"                # 커서 숨기기
echo -e "\033[?25h"                # 커서 보이기

# 키보드 입력 테스트
read -p "Press Enter: "
read -n 1 -p "Press any key: "

# 자동완성 테스트
echo "Type 'ls /u' and press Tab twice"

# 히스토리 테스트
history | tail -5

# 작업 제어 테스트
sleep 100 &
jobs
fg
# Ctrl+Z 테스트
# Ctrl+C 테스트
```

## 🔄 우회 기법들

### 🛠️ 바이너리 제한 우회

```bash
# Python 바이너리가 다른 위치에 있는 경우
/usr/bin/python -c 'import pty; pty.spawn("/bin/bash")'
/usr/bin/python3 -c 'import pty; pty.spawn("/bin/bash")'
/usr/local/bin/python -c 'import pty; pty.spawn("/bin/bash")'

# Python 버전 자동 탐지
for py in python python2 python3 python2.7 python3.6 python3.8; do
    which $py >/dev/null 2>&1 && $py -c 'import pty; pty.spawn("/bin/bash")' && break
done

# Script 바이너리가 다른 위치에 있는 경우
/usr/bin/script -qc /bin/bash /dev/null
/bin/script -qc /bin/bash /dev/null

# 대안 쉘들 시도
chsh -s /bin/bash
chsh -s /bin/zsh
exec /bin/bash
exec /bin/zsh
exec /bin/dash

# Socat 경로 다를 때
/usr/bin/socat file:`tty`,raw,echo=0 tcp-listen:4444
/usr/local/bin/socat file:`tty`,raw,echo=0 tcp-listen:4444
```

### 📁 권한 제한 우회

```bash
# 홈 디렉토리 접근 불가시
cd /tmp && python -c 'import pty; pty.spawn("/bin/bash")'
cd /var/tmp && python -c 'import pty; pty.spawn("/bin/bash")'

# 쓰기 권한 없는 디렉토리에서
python -c 'import pty, os; os.chdir("/tmp"); pty.spawn("/bin/bash")'

# 환경 변수 설정 불가시
python -c 'import pty, os; os.environ["TERM"]="xterm"; pty.spawn("/bin/bash")'

# bashrc 로드 불가시
bash --noprofile --norc

# 임시 설정 파일 생성
echo 'export PS1="\u@\h:\w\$ "' > /tmp/.bashrc
bash --rcfile /tmp/.bashrc

# 메모리 내 설정
bash -c 'export TERM=xterm; export PS1="\u@\h:\w\$ "; exec bash'
```

### 🚫 모듈 Import 제한 우회

```bash
# pty 모듈 없을 때
python -c "import subprocess; subprocess.call(['/bin/bash'])"
python -c "import os; os.system('/bin/bash')"

# 모든 모듈 제한시
python -c "exec(open('/usr/lib/python2.7/pty.py').read()); spawn('/bin/bash')"

# C 코드로 TTY 생성
cat > /tmp/pty.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pty.h>

int main() {
    char *args[] = {"/bin/bash", NULL};
    forkpty(NULL, NULL, NULL, NULL);
    execve("/bin/bash", args, NULL);
    return 0;
}
EOF

gcc -o /tmp/pty /tmp/pty.c -lutil && /tmp/pty

# 어셈블리로 직접 구현 (고급)
cat > /tmp/shell.s << 'EOF'
.section .data
shell: .ascii "/bin/bash\0"

.section .text
.globl _start
_start:
    mov $59, %rax      # execve syscall
    mov $shell, %rdi   # program name
    mov $0, %rsi       # argv
    mov $0, %rdx       # envp
    syscall
EOF

as -64 -o /tmp/shell.o /tmp/shell.s && ld -o /tmp/shell /tmp/shell.o && /tmp/shell
```

### 🔐 네트워크 보안 우회

```bash
# 로컬 연결을 통한 TTY
nc -l -p 31337 &
python -c 'import pty; pty.spawn("/bin/bash")' | nc localhost 31337

# Unix 소켓을 이용한 TTY
socat unix-listen:/tmp/tty,fork exec:/bin/bash,pty,stderr,setpgid,sigint,sane &
socat - unix-connect:/tmp/tty

# Named Pipe를 이용한 TTY
mkfifo /tmp/pipe
cat /tmp/pipe | /bin/bash 2>&1 | tee /tmp/pipe &

# 메모리 파일시스템 활용
mount -t tmpfs tmpfs /tmp/mem
cd /tmp/mem && python -c 'import pty; pty.spawn("/bin/bash")'
```

## 🤖 자동화 도구 명령어

### 🔧 자동 TTY 업그레이드 스크립트

```bash
#!/bin/bash
# 자동 TTY 업그레이드 스크립트

echo "[+] Starting TTY upgrade process..."

# 1단계: 사용 가능한 TTY 생성 방법 탐지
echo "[+] Detecting available TTY upgrade methods..."

METHODS=(
    "python -c 'import pty; pty.spawn(\"/bin/bash\")'"
    "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
    "script -qc /bin/bash /dev/null"
    "/usr/bin/script -qc /bin/bash /dev/null"
    "expect -c 'spawn /bin/bash; interact'"
    "perl -e 'exec \"/bin/bash\"'"
    "ruby -e 'exec \"/bin/bash\"'"
    "socat file:\`tty\`,raw,echo=0 tcp-listen:31337"
)

for method in "${METHODS[@]}"; do
    echo "[+] Trying: $method"
    if eval "$method" 2>/dev/null; then
        echo "[+] Success with: $method"
        break
    fi
done

# 2단계: 터미널 환경 설정
echo "[+] Setting up terminal environment..."
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows 50 columns 200

# 3단계: Bash 환경 개선
echo "[+] Improving bash environment..."
export HISTFILE=~/.bash_history
export HISTSIZE=1000
export PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '

echo "[+] TTY upgrade completed!"
```

### 🐍 Python TTY 업그레이드 자동화

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import pty

def upgrade_tty():
    """자동 TTY 업그레이드"""
    print("[+] Starting TTY upgrade...")

    try:
        # 1. PTY 생성
        print("[+] Creating PTY...")
        pty.spawn("/bin/bash")

    except ImportError:
        print("[-] PTY module not available, trying alternatives...")

        # 대안 방법들
        alternatives = [
            "script -qc /bin/bash /dev/null",
            "expect -c 'spawn /bin/bash; interact'",
            "perl -e 'exec \"/bin/bash\"'",
            "ruby -e 'exec \"/bin/bash\"'"
        ]

        for cmd in alternatives:
            print(f"[+] Trying: {cmd}")
            try:
                os.system(cmd)
                break
            except:
                continue

    # 환경 설정
    print("[+] Setting environment...")
    os.environ['TERM'] = 'xterm-256color'
    os.environ['SHELL'] = '/bin/bash'

    # 터미널 크기 설정
    os.system('stty rows 50 columns 200')

    print("[+] TTY upgrade completed!")

if __name__ == "__main__":
    upgrade_tty()
```

### 🔄 원라이너 생성기

```bash
#!/bin/bash
# TTY 업그레이드 원라이너 생성기

generate_oneliners() {
    echo "=== TTY Upgrade One-liners ==="

    echo "# Python 2/3 Auto-detect"
    echo "python -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null || python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"

    echo -e "\n# Script method"
    echo "script -qc /bin/bash /dev/null"

    echo -e "\n# Expect method"
    echo "expect -c 'spawn /bin/bash; interact'"

    echo -e "\n# Perl method"
    echo "perl -e 'exec \"/bin/bash\"'"

    echo -e "\n# Ruby method"
    echo "ruby -e 'exec \"/bin/bash\"'"

    echo -e "\n# Node.js method"
    echo "node -e \"require('child_process').spawn('/bin/bash', {stdio: [0, 1, 2]});\""

    echo -e "\n# Full upgrade sequence"
    echo "python -c 'import pty; pty.spawn(\"/bin/bash\")'; export TERM=xterm; stty rows 50 columns 200"

    echo -e "\n# Background method"
    echo "(python -c 'import pty; pty.spawn(\"/bin/bash\")' &); sleep 1; fg"

    echo -e "\n# Multiple attempts"
    echo "for cmd in 'python' 'python3' 'script -qc /bin/bash /dev/null'; do \$cmd -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null && break; done"
}

generate_oneliners
```

### 🎛️ 터미널 설정 자동화

```bash
#!/bin/bash
# 터미널 설정 자동화 스크립트

setup_terminal() {
    echo "[+] Configuring terminal settings..."

    # 기본 환경 변수
    export TERM=xterm-256color
    export SHELL=/bin/bash
    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

    # 터미널 크기 설정
    if command -v stty >/dev/null 2>&1; then
        stty rows 50 columns 200
        stty sane
    fi

    # 히스토리 설정
    export HISTFILE=~/.bash_history
    export HISTSIZE=1000
    export HISTFILESIZE=2000
    export HISTCONTROL=ignoredups:ignorespace

    # 프롬프트 설정
    export PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '

    # 별칭 설정
    alias ls='ls --color=auto' 2>/dev/null
    alias grep='grep --color=auto' 2>/dev/null
    alias ll='ls -alF' 2>/dev/null
    alias la='ls -A' 2>/dev/null
    alias l='ls -CF' 2>/dev/null

    # 색상 설정
    if [ -x /usr/bin/dircolors ]; then
        test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    fi

    # Vi 모드 설정 (선택사항)
    # set -o vi

    echo "[+] Terminal configuration completed!"
}

# 실행
setup_terminal

# Bash completion 로드 (있는 경우)
if [ -f /etc/bash_completion ] && ! shopt -oq posix; then
    . /etc/bash_completion
fi

# 로컬 설정 로드 (있는 경우)
if [ -f ~/.bashrc_local ]; then
    . ~/.bashrc_local
fi
```

## 🚨 문제 해결

### ❌ TTY 업그레이드가 안 될 때

```bash
# 1. Python 설치 확인
which python
which python2
which python3
ls /usr/bin/python*

# 2. Python 버전별 시도
python --version
python2 --version
python3 --version

# 각 버전으로 시도
python -c 'import pty; pty.spawn("/bin/bash")'
python2 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 3. pty 모듈 확인
python -c 'import pty; print("pty available")'

# 4. 대안 방법들 시도
script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null
expect -c 'spawn /bin/bash; interact'

# 5. 수동 TTY 생성
exec /bin/bash
bash -i
/bin/bash -i

# 6. 다른 쉘 시도
exec /bin/sh
exec /bin/zsh
exec /bin/dash
```

### 🔧 터미널 설정 문제

```bash
# 1. TERM 변수 문제
echo $TERM
export TERM=xterm
export TERM=xterm-256color
export TERM=screen

# 2. 터미널 크기 문제
stty size
stty rows 24 columns 80
stty rows 50 columns 200

# 3. 색상 지원 문제
tput colors
echo -e "\033[31mTest\033[0m"

# 4. 키보드 매핑 문제
stty -a
stty sane
stty intr ^C
stty susp ^Z

# 5. 백스페이스 문제
stty erase ^H
stty erase ^?

# 6. 자동완성 문제
bind "TAB:menu-complete"
set completion-ignore-case on
```

### 🚫 권한 및 제한 문제

```bash
# 1. rbash 제한 우회
echo $SHELL
export PATH=/bin:/usr/bin:$PATH
cd /tmp && bash

# 2. 환경 변수 제한
env
export TERM=xterm
unset TMOUT

# 3. 홈 디렉토리 접근 문제
cd /tmp
cd /var/tmp
cd /dev/shm

# 4. 쓰기 권한 문제
ls -la ~/.bashrc
touch ~/.bashrc
echo 'export PS1="\u@\h:\w\$ "' >> ~/.bashrc

# 5. 실행 권한 문제
chmod +x /tmp/script
ls -la /bin/bash
```

### 🌐 네트워크 연결 문제

```bash
# 1. 백그라운드 TTY 업그레이드
(python -c 'import pty; pty.spawn("/bin/bash")' &)
sleep 1
fg

# 2. 로컬 소켓 활용
mkfifo /tmp/tty
cat /tmp/tty | /bin/bash 2>&1 | tee /tmp/tty &

# 3. SSH 로컬 연결
ssh localhost
ssh 127.0.0.1

# 4. 프로세스 대체
exec 3<>/dev/tcp/127.0.0.1/22
cat <&3 | /bin/bash 2>&3 >&3

# 5. Unix 도메인 소켓
socat unix-listen:/tmp/sock,fork exec:/bin/bash,pty &
socat - unix-connect:/tmp/sock
```

### 🎯 고급 문제 해결

```bash
# 1. 메모리 부족 문제
ulimit -a
ulimit -v unlimited

# 2. 프로세스 제한 문제
ulimit -u
ulimit -u unlimited

# 3. 파일 디스크립터 문제
ulimit -n
ulimit -n 4096

# 4. 시간 제한 문제
unset TMOUT
export TMOUT=0

# 5. 로케일 문제
locale
export LC_ALL=C
export LANG=C

# 6. 특수 문자 문제
stty -parenb -parodd cs8 -hupcl -cstopb cread -clocal -crtscts
stty -ignbrk brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany -imaxbel
stty opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
stty isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke
```

### 🔄 자동 복구 메커니즘

```bash
# 터미널 자동 복구 함수
fix_terminal() {
    echo "[+] Attempting terminal recovery..."

    # 기본 설정 복원
    stty sane 2>/dev/null
    reset 2>/dev/null
    clear 2>/dev/null

    # 환경 변수 설정
    export TERM=xterm-256color
    export SHELL=/bin/bash

    # 터미널 크기 재설정
    stty rows 24 columns 80 2>/dev/null

    # 키 매핑 복원
    stty intr ^C susp ^Z quit ^\ 2>/dev/null

    echo "[+] Terminal recovery completed"
}

# 별칭으로 등록
alias fix='fix_terminal'

# 자동 실행 설정
trap 'fix_terminal' SIGWINCH
```

## 📊 성공 판정 기준

### ✅ TTY 업그레이드 성공

- **TTY 확인**: `tty` 명령어가 `/dev/pts/X` 형태로 응답
- **신호 처리**: Ctrl+C, Ctrl+Z가 정상적으로 작동
- **자동완성**: Tab 키로 파일명/명령어 자동완성 동작
- **히스토리**: 위/아래 화살표로 명령어 히스토리 탐색
- **색상 지원**: `ls --color=auto`로 색상 출력 확인

### ✅ 터미널 기능 확인

- **화면 제어**: `clear` 명령어로 화면 지우기
- **커서 이동**: Home, End, 화살표 키 정상 동작
- **라인 편집**: 백스페이스, Delete 키 정상 동작
- **프롬프트**: 색상이 있는 프롬프트 표시
- **환경 변수**: `$TERM`, `$SHELL` 등 적절히 설정

### ✅ 고급 기능 확인

- **Vi/Emacs 모드**: 라인 편집 모드 설정 가능
- **작업 제어**: 백그라운드 작업 실행 및 제어
- **파이프라인**: 복잡한 명령어 파이프라인 실행
- **리다이렉션**: 입출력 리다이렉션 정상 동작
- **별칭**: 명령어 별칭 설정 및 사용

### ⏰ 시간 관리

- **즉시 업그레이드**: 쉘 획득 후 1분 내 TTY 업그레이드 시도
- **기본 설정**: 3분 내 터미널 환경 설정 완료
- **문제 해결**: 5분 내 주요 문제들 해결 시도
- **포기 기준**: 10분 이내 해결 안되면 기본 쉘로 진행

**우선순위**: 기능성 > 완벽성 (시험 시간 고려)

## 💡 OSCP 실전 팁

- **즉시 시도**: 쉘 획득 즉시 TTY 업그레이드 (나중에 잊기 쉬움)
- **백업 계획**: Python 안될 때 script, expect 등 대안 준비
- **환경 저장**: 성공적인 설정을 `.bashrc`에 저장하여 재연결시 활용
- **탭 완성**: 자동완성은 시험에서 오타 방지에 매우 중요
- **히스토리**: 명령어 히스토리로 이전 시도 내용 추적
- **시간 절약**: 완벽한 설정보다는 기본 기능부터 우선 확보
- **문서화**: 성공한 업그레이드 방법을 노트에 기록
