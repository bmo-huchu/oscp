# 🏆 OSCP Ultimate Cheat Sheet

> **"Try Harder"를 "Try Smarter"로 만드는 완벽한 시험 동반자**

## 🎯 이 Cheat Sheet의 목적

**5시간 시험에서 1초라도 빨리 답을 찾아 실행할 수 있도록 설계된 실전용 레퍼런스**

- ❌ 학습용 자료가 아님
- ❌ 이론 설명서가 아님
- ✅ **시험 중 빠른 실행용 명령어 모음**
- ✅ **막혔을 때 즉시 참조할 수 있는 해결책**

---

## 🚀 시험 당일 사용법 (단계별)

### 🎬 Phase 0: 시험 시작 전 (5분)

```bash
# 1. 필수 북마크 설정 (브라우저에)
- PORT-ATTACKS/80-443-web.md      # 가장 자주 쓸 파일
- SHELLS/reverse-shells.md         # 두 번째로 자주 쓸 파일
- EMERGENCY/cant-get-shell.md      # 막혔을 때 #1
- EMERGENCY/privesc-stuck.md       # 막혔을 때 #2

# 2. 창 배치
- 메인 모니터: Kali Linux
- 서브 모니터: 이 GitHub 페이지 (또는 로컬 복사본)
- 노트 앱: CherryTree/Obsidian 준비
```

### 🔍 Phase 1: 정찰 (첫 30-45분)

**[📋 RECONNAISSANCE/checklist.md](RECONNAISSANCE/checklist.md) 파일을 열고 따라하기**

```bash
# 즉시 실행할 명령어들 (IP를 타겟으로 변경)
nmap -sC -sV -oA initial {TARGET_IP}
nmap -p- -oA full-scan {TARGET_IP} &
gobuster dir -u http://{TARGET_IP} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt &

# 병렬로 실행하면서 결과 기다리기
```

**⚠️ 중요: 포트 스캔 결과가 나오는 즉시 다음 단계로!**

### 🚪 Phase 2: 포트별 공격 (결과 나올 때마다)

**포트 발견 → 즉시 해당 파일로 점프**

| 포트 발견 | 즉시 열 파일                                               | 예상 소요시간 |
| --------- | ---------------------------------------------------------- | ------------- |
| 80/443    | [PORT-ATTACKS/80-443-web.md](PORT-ATTACKS/80-443-web.md)   | 60-90분       |
| 139/445   | [PORT-ATTACKS/139-445-smb.md](PORT-ATTACKS/139-445-smb.md) | 20-30분       |
| 22        | [PORT-ATTACKS/22-ssh.md](PORT-ATTACKS/22-ssh.md)           | 15분          |
| 기타      | [PORT-ATTACKS/](PORT-ATTACKS/) 해당 파일                   | 15-30분       |

### 🐚 Phase 3: 쉘 획득 (공격 성공 후)

**[🐚 SHELLS/reverse-shells.md](SHELLS/reverse-shells.md) → OS/언어별 페이로드 선택**

```bash
# 리스너 준비 (항상 먼저!)
nc -lvnp 4444

# 상황별 페이로드 선택
- PHP 웹앱 → php reverse shell
- ASP.NET → aspx reverse shell
- Linux 명령어 실행 → bash reverse shell
- Windows 명령어 실행 → powershell reverse shell
```

### 🔺 Phase 4: 권한 상승 (쉘 획득 후)

**OS 확인 후 해당 폴더로**

```bash
# OS 확인
whoami && id       # Linux
whoami /all        # Windows

# Linux인 경우
→ PRIVILEGE-ESCALATION/linux-privesc/checklist.md

# Windows인 경우
→ PRIVILEGE-ESCALATION/windows-privesc/checklist.md
```

---

## ⏰ 시간 관리 전략

### 🕐 시간 배분 가이드라인

- **정찰**: 30-45분 (전체 스캔 + 초기 열거)
- **초기 침투**: 60-90분 (foothold 확보)
- **권한 상승**: 45-60분 (root/admin 권한)
- **문서화**: 30분 (증명 스크린샷 + 노트 정리)
- **버퍼**: 30분 (예상 못한 문제 해결)

### ⏱️ 시간별 체크포인트

| 경과 시간 | 체크포인트     | 행동                                                                |
| --------- | -------------- | ------------------------------------------------------------------- |
| 30분      | 포트스캔 완료? | 안됐으면 범위 줄이기                                                |
| 1시간     | foothold 진전? | 없으면 다른 서비스 시도                                             |
| 2시간     | 쉘 획득?       | 안됐으면 [EMERGENCY/cant-get-shell.md](EMERGENCY/cant-get-shell.md) |
| 3시간     | 권한상승 진전? | 안됐으면 [EMERGENCY/privesc-stuck.md](EMERGENCY/privesc-stuck.md)   |
| 4시간     | root 권한?     | 안됐으면 다른 머신 고려                                             |

---

## 🆘 막혔을 때 응급 대응법

### 🚫 쉘을 못 얻겠을 때

**→ [EMERGENCY/cant-get-shell.md](EMERGENCY/cant-get-shell.md) 즉시 확인**

```
일반적인 원인들:
1. 방화벽/필터링 → 다른 포트 시도 (53, 443, 80)
2. 페이로드 문제 → 다른 언어로 시도
3. 인코딩 문제 → base64, URL 인코딩
4. 권한 문제 → 다른 업로드 위치 시도
```

### ⬆️ 권한상승이 안 될 때

**→ [EMERGENCY/privesc-stuck.md](EMERGENCY/privesc-stuck.md) 즉시 확인**

```
놓치기 쉬운 것들:
1. 다른 사용자 홈 디렉토리 확인
2. 내부 서비스 (127.0.0.1) 확인
3. 숨겨진 cron job 확인
4. 환경변수 확인
```

### 😰 완전히 막혔을 때

**→ [EMERGENCY/exam-panic.md](EMERGENCY/exam-panic.md) 읽고 진정하기**

---

## 🎯 파일별 사용법

### 📋 체크리스트 파일들

**각 단계별로 순서대로 따라하는 파일들**

- `RECONNAISSANCE/checklist.md` - 정찰 단계
- `WEB-EXPLOITATION/web-checklist.md` - 웹 공격 단계
- `PRIVILEGE-ESCALATION/*/checklist.md` - 권한상승 단계

### ⚡ 원라이너 파일들

**즉시 복사-붙여넣기용 명령어 모음**

- `SHELLS/reverse-shells.md` - 리버스쉘 명령어들
- `REFERENCE/one-liners.md` - 자주 쓰는 명령어들
- `TOOLS/gobuster.md` - gobuster 명령어 변형들

### 🎯 포트별 공격 파일들

**해당 포트 발견시 즉시 열어볼 파일들**

- 각 파일은 "발견 → 열거 → 공격 → 익스플로잇" 순서로 구성

---

## 💡 효과적인 사용 팁

### 🔖 북마크 전략

```
브라우저 북마크 바에 추가 (순서대로):
1. 이 README (시작점)
2. 80-443-web.md (가장 자주 사용)
3. reverse-shells.md (두 번째로 자주 사용)
4. cant-get-shell.md (응급용 #1)
5. privesc-stuck.md (응급용 #2)
```

### 📱 멀티 디바이스 활용

- **메인 PC**: Kali Linux 작업
- **서브 모니터**: GitHub 이 cheat sheet
- **태블릿/폰**: 시간 관리용 ([TIME-MANAGEMENT.md](TIME-MANAGEMENT.md))

### 📝 노트 연동

```
CherryTree/Obsidian 노트 구조:
├── Target 1
│   ├── Reconnaissance (이 cheat sheet 참조)
│   ├── Web Attacks (이 cheat sheet 참조)
│   ├── Privilege Escalation (이 cheat sheet 참조)
│   └── Screenshots
├── Target 2
└── ...
```

---

## 🏁 시험 성공 전략

### ✅ 시험 전날 체크리스트

- [ ] 이 README 완전히 숙지
- [ ] 주요 파일들 북마크 완료
- [ ] 노트 템플릿 준비
- [ ] 가상머신 환경 테스트
- [ ] 필요한 도구들 설치 확인

### 🎯 시험 당일 마음가짐

1. **속도 > 완벽**: 완벽한 이해보다는 빠른 실행
2. **실행 > 분석**: 오래 생각하지 말고 일단 시도
3. **다음 > 고집**: 안 되면 빨리 다른 방법 시도
4. **체크리스트 > 직감**: 감에 의존하지 말고 체크리스트 따르기

### 🚀 합격을 위한 마지막 조언

**이 cheat sheet의 핵심 가치:**

- 막막한 상황에서 **명확한 다음 단계** 제시
- 패닉 상황에서 **체계적 접근** 복원
- 시간 압박 속에서 **빠른 실행** 가능

**잊지 마세요:**

- 모든 문제에는 해답이 있습니다
- 이 cheat sheet는 여러분의 든든한 동반자입니다
- **여러분은 충분히 준비되어 있습니다!**

---

## 📞 추가 지원

### 🔄 지속적인 업데이트

이 cheat sheet는 실제 시험 경험을 바탕으로 지속적으로 개선됩니다.

- 새로운 기법 발견시 즉시 추가
- 효율적이지 않은 부분 개선
- 시험 패턴 변화에 맞춘 업데이트

### 🤝 팀 공유

팀 전체가 OSCP를 준비한다면:

- 이 구조를 팀 표준으로 사용
- 각자 발견한 팁들을 공유하여 cheat sheet 개선
- 모의 시험에서 이 cheat sheet 활용 연습

---

## 🏆 최종 메시지

**회사 목표 달성과 개인 성장, 두 마리 토끼를 모두 잡으세요!**

이 cheat sheet는 단순한 명령어 모음이 아닙니다.
여러분의 **시험 성공을 위한 전략적 도구**입니다.

**Try Harder**를 **Try Smarter**로 바꿔서,
확실하게 합격하시길 진심으로 응원합니다! 🚀

---

_"The best preparation for tomorrow is doing your best today."_
_- H. Jackson Brown Jr._
