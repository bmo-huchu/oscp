# 🌐 WEB DISCOVERY

> **목표: 웹 서비스 발견 후 15-20분 내에 모든 공격 표면 매핑**

## ⚡ 즉시 실행할 명령어들

### 🚀 웹 서비스 발견 즉시 (병렬 실행)

```bash
# 1. 기본 웹 정보 수집
curl -I http://{IP}
curl -I https://{IP}

# 2. 디렉토리 스캔 시작 (백그라운드)
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,asp,aspx -t 50 -o gobuster-80.txt &

# 3. HTTPS 디렉토리 스캔 (HTTPS 포트가 열린 경우)
gobuster dir -u https://{IP} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,asp,aspx -t 50 -k -o gobuster-443.txt &

# 4. 웹 기술 스택 확인
whatweb http://{IP}
whatweb https://{IP}

# 5. 취약점 스캔 시작
nikto -h http://{IP} -o nikto-80.txt &
nikto -h https://{IP} -o nikto-443.txt &
```

### ⚡ 기본 파일 확인 (즉시 실행)

```bash
# 로봇츠 파일
curl http://{IP}/robots.txt
curl https://{IP}/robots.txt

# 사이트맵
curl http://{IP}/sitemap.xml
curl https://{IP}/sitemap.xml

# 일반적인 숨겨진 파일들
curl http://{IP}/.htaccess
curl http://{IP}/web.config
curl http://{IP}/crossdomain.xml
curl http://{IP}/.git/config
curl http://{IP}/.svn/entries
```

---

## 📋 단계별 체크리스트

### 🎯 Phase 1: 기본 발견 (5분)

- [ ] **웹 서버 응답 확인** `curl -I http://{IP}`
- [ ] **서버 헤더 정보 수집** (Server, X-Powered-By 등)
- [ ] **리다이렉션 확인** (301, 302 응답)
- [ ] **HTTPS 지원 확인** `curl -I https://{IP}`
- [ ] **기본 페이지 확인** `curl http://{IP}`

### 🔍 Phase 2: 기술 스택 식별 (5분)

- [ ] **웹 기술 스택 스캔** `whatweb http://{IP}`
- [ ] **CMS 식별** (WordPress, Joomla, Drupal 등)
- [ ] **프레임워크 식별** (Laravel, Spring, Django 등)
- [ ] **웹 서버 식별** (Apache, Nginx, IIS 등)
- [ ] **프로그래밍 언어 식별** (PHP, ASP.NET, JSP 등)

### 📁 Phase 3: 디렉토리/파일 열거 (10분)

- [ ] **기본 디렉토리 스캔 시작** `gobuster dir`
- [ ] **확장자별 파일 스캔** (-x php,asp,aspx,jsp,html,txt)
- [ ] **공통 파일 확인** (robots.txt, sitemap.xml)
- [ ] **백업 파일 확인** (.bak, .old, ~ 등)
- [ ] **설정 파일 확인** (web.config, .htaccess)

### 🔒 Phase 4: 보안 스캔 (백그라운드)

- [ ] **Nikto 스캔 시작** `nikto -h http://{IP}`
- [ ] **SSL 정보 확인** (HTTPS인 경우)
- [ ] **보안 헤더 확인** (HSTS, CSP 등)
- [ ] **취약점 스캔 실행** `nmap --script http-vuln-*`

---

## 🎯 상황별 대응

### 🏠 Apache 웹서버 발견시

```bash
# Apache 특화 스캔
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,cgi,pl

# Apache 설정 파일들
curl http://{IP}/.htaccess
curl http://{IP}/.htpasswd
curl http://{IP}/server-status
curl http://{IP}/server-info

# CGI 디렉토리 확인
gobuster dir -u http://{IP}/cgi-bin/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x cgi,pl,sh

# 아파치 모듈 정보
nmap --script http-apache-server-status {IP}
```

### 🪟 IIS 웹서버 발견시

```bash
# IIS 특화 스캔
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x asp,aspx,config,txt

# IIS 특정 파일들
curl http://{IP}/web.config
curl http://{IP}/global.asax
curl http://{IP}/app.config
curl http://{IP}/bin/
curl http://{IP}/App_Data/

# IIS 단축명 스캔
java -jar iis_shortname_scanner.jar 2 20 http://{IP}/

# WebDAV 확인
davtest -url http://{IP}
cadaver http://{IP}
```

### 🔧 Nginx 웹서버 발견시

```bash
# Nginx 특화 스캔
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,conf

# Nginx 설정 파일
curl http://{IP}/nginx.conf
curl http://{IP}/.well-known/
curl http://{IP}/status

# PHP-FPM 확인 (Nginx + PHP)
curl http://{IP}/status?full
curl http://{IP}/ping
```

### 📱 CMS별 특화 스캔

#### WordPress 발견시

```bash
# WordPress 확인
curl http://{IP}/wp-admin/
curl http://{IP}/wp-content/
curl http://{IP}/wp-includes/

# WPScan 실행
wpscan --url http://{IP} --enumerate p,t,u

# WordPress 버전 확인
curl http://{IP}/wp-admin/install.php
curl http://{IP}/readme.html
curl http://{IP}/license.txt

# 플러그인 열거
gobuster dir -u http://{IP}/wp-content/plugins/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

#### Joomla 발견시

```bash
# Joomla 확인
curl http://{IP}/administrator/
curl http://{IP}/configuration.php
curl http://{IP}/README.txt

# JoomScan 실행
joomscan -u http://{IP}

# Joomla 버전 확인
curl http://{IP}/administrator/manifests/files/joomla.xml
curl http://{IP}/language/en-GB/en-GB.xml
```

#### Drupal 발견시

```bash
# Drupal 확인
curl http://{IP}/user/login
curl http://{IP}/admin/
curl http://{IP}/CHANGELOG.txt

# Droopescan 실행
droopescan scan drupal -u http://{IP}

# Drupal 버전 확인
curl http://{IP}/CHANGELOG.txt
curl http://{IP}/core/CHANGELOG.txt
```

### 🗄️ 데이터베이스 관리 도구 발견시

```bash
# phpMyAdmin
curl http://{IP}/phpmyadmin/
curl http://{IP}/pma/
curl http://{IP}/mysql/
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt | grep -i "phpmyadmin\|pma\|mysql"

# Adminer
curl http://{IP}/adminer.php
curl http://{IP}/adminer/

# WebSQL
curl http://{IP}/websql/
curl http://{IP}/sqlweb/
```

### 🔐 인증 시스템 발견시

```bash
# 로그인 페이지들
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | grep -i "login\|admin\|auth\|portal"

# 기본 자격증명 확인
curl -u admin:admin http://{IP}/admin/
curl -u root:root http://{IP}/admin/
curl -u administrator:password http://{IP}/admin/

# HTTP 기본 인증 브루트포스
hydra -l admin -P /usr/share/wordlists/rockyou.txt {IP} http-get /admin/
```

---

## 🚨 문제 해결

### 🔒 403 Forbidden 많이 나올 때

```bash
# 다른 워드리스트 시도
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt

# 대소문자 변형 시도
gobuster dir -u http://{IP} -w wordlist.txt -s 200,204,301,302,307,401

# 다른 도구 사용
dirb http://{IP}
dirsearch -u http://{IP} -e php,asp,aspx,jsp,html

# User-Agent 변경
gobuster dir -u http://{IP} -w wordlist.txt -a "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
```

### 📁 스캔 결과가 없을 때

```bash
# 작은 워드리스트로 시작
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirb/small.txt

# 다른 확장자 시도
gobuster dir -u http://{IP} -w wordlist.txt -x txt,bak,old,~,conf,cfg,ini

# 백업 파일 확인
gobuster dir -u http://{IP} -w wordlist.txt -x .bak,.backup,.old,.txt,.zip,.tar.gz

# 숨김 파일 확인
gobuster dir -u http://{IP} -w wordlist.txt -a ".*"

# 포트 변경하여 시도
gobuster dir -u http://{IP}:8080 -w wordlist.txt
gobuster dir -u http://{IP}:8000 -w wordlist.txt
```

### 🐌 스캔이 느릴 때

```bash
# 스레드 수 조정
gobuster dir -u http://{IP} -w wordlist.txt -t 100

# 더 작은 워드리스트 사용
gobuster dir -u http://{IP} -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt

# 시간 제한 설정
gobuster dir -u http://{IP} -w wordlist.txt --timeout 10s

# 다른 도구로 병렬 실행
ffuf -w wordlist.txt -u http://{IP}/FUZZ -t 100
```

### 🚫 WAF/CDN 감지시

```bash
# User-Agent 변경
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" http://{IP}

# 다른 헤더 추가
curl -H "X-Originating-IP: 127.0.0.1" -H "X-Forwarded-For: 127.0.0.1" http://{IP}

# 프록시 체인 사용
proxychains gobuster dir -u http://{IP} -w wordlist.txt

# IP 직접 접근 시도
nslookup {DOMAIN}
curl -H "Host: {DOMAIN}" http://{REAL_IP}/
```

### 🔍 추가 정보 수집 필요시

```bash
# 소스 코드 분석
curl http://{IP} | grep -i "version\|powered\|generator\|framework"

# 메타 태그 확인
curl http://{IP} | grep -i "<meta"

# JavaScript 파일 분석
gobuster dir -u http://{IP} -w wordlist.txt -x js
curl http://{IP}/main.js | grep -i "api\|endpoint\|url\|path"

# CSS 파일에서 경로 정보
gobuster dir -u http://{IP} -w wordlist.txt -x css
curl http://{IP}/style.css | grep -i "url\|path"

# HTTP 메소드 확인
nmap --script http-methods {IP}
curl -X OPTIONS http://{IP} -v
```

---

## 🔄 서브도메인 열거 (도메인이 있는 경우)

### 🌐 서브도메인 발견

```bash
# Gobuster를 이용한 서브도메인 스캔
gobuster vhost -u {DOMAIN} -w /usr/share/wordlists/subdomains-top1million-5000.txt

# Sublist3r 사용
sublist3r -d {DOMAIN}

# 와일드카드 DNS 확인
dig *.{DOMAIN}

# 인증서 투명성 로그에서 서브도메인 찾기
curl -s "https://crt.sh/?q=%25.{DOMAIN}&output=json" | jq -r '.[].name_value' | sort -u

# DNS 존 전송 시도
dig axfr {DOMAIN} @{IP}
dnsrecon -d {DOMAIN} -t axfr
```

### 📧 이메일 주소 수집

```bash
# theHarvester 사용
theHarvester -d {DOMAIN} -b google,bing,yahoo

# OSINT 도구들
maltego
recon-ng
```

---

## ⏱️ 시간 효율성 팁

### 🎯 15분 안에 완료해야 할 것들

- [ ] 기본 웹 서버 정보 수집
- [ ] 디렉토리 스캔 시작 (백그라운드)
- [ ] CMS/프레임워크 식별
- [ ] 기본 파일들 확인 (robots.txt 등)

### 🔍 30분 안에 완료해야 할 것들

- [ ] 모든 디렉토리 스캔 완료
- [ ] 취약점 스캔 결과 확인
- [ ] 중요한 파일/디렉토리 식별
- [ ] 다음 공격 벡터 결정

### 📊 완료 기준

웹 발견 단계는 다음 조건이 만족되면 완료:

- [ ] 모든 접근 가능한 디렉토리/파일 매핑 완료
- [ ] 웹 기술 스택 완전히 식별
- [ ] 잠재적 공격 벡터 리스트 작성
- [ ] 다음 단계에서 집중할 영역 결정

**다음 단계**: `WEB-EXPLOITATION/` 해당 공격 기법 파일로 이동!
