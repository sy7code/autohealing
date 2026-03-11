<p align="center">
  <h1 align="center">🛡️ Auto-Healing DevSecOps Engine</h1>
  <p align="center">
    <strong>GitHub 커밋 감지 → 보안 취약점 자동 스캔 → AI 자동 수정 → PR 자동 생성</strong>
    <br/>
    지능형 DevSecOps 자동화 엔진 (Personal Portfolio Project)
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Java-21-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white" />
  <img src="https://img.shields.io/badge/Spring_Boot-3.4-6DB33F?style=for-the-badge&logo=spring-boot&logoColor=white" />
  <img src="https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white" />
  <img src="https://img.shields.io/badge/Next.js-000000?style=for-the-badge&logo=next.js&logoColor=white" />
  <img src="https://img.shields.io/badge/Azure_SDK-0078D4?style=for-the-badge&logo=microsoft-azure&logoColor=white" />
</p>

---

## 📋 목차

- [프로젝트 소개](#-프로젝트-소개)
- [시스템 아키텍처](#-시스템-아키텍처)
- [기술 스택](#-기술-스택)
- [주요 기능](#-주요-기능)
- [프로젝트 구조](#-프로젝트-구조)
- [실행 방법](#-실행-방법)
- [환경 변수](#-환경-변수)
- [API 문서](#-api-문서)
- [개발 단계별 구현 상세 (Phases)](#-개발-단계별-구현-상세-phases)
- [보안 고려 사항](#-보안-고려-사항)

---

## 🎯 프로젝트 소개

**Auto-Healing DevSecOps Engine**은 소프트웨어 개발 라이프사이클에 보안을 자동으로 내재화하는 **지능형 DevSecOps 자동화 엔진/툴**입니다.

개발자가 GitHub에 코드를 Push하면, 시스템이 자동으로:

1. **🔍 취약점 스캔**: Snyk(SAST) + Azure(CSPM) + 커스텀 스캐너를 병렬로 실행하여 코드 및 인프라 취약점을 감지합니다.
2. **🤖 AI 자동 분석/수정**: Gemini AI가 취약점의 원본 코드를 분석하고, 수정 패치 코드를 자동 생성합니다.
3. **🛡️ 안전성 검증**: AI가 생성한 코드를 AST(추상 구문 트리) 분석, 컴파일 검증, 민감정보 탐지 등 3중 안전장치로 검증합니다.
4. **📝 자동 PR 생성**: 검증을 통과한 패치 코드를 GitHub PR로 자동 생성합니다.
5. **🎫 Jira 티켓 자동 관리**: 취약점 발견 시 자동으로 Jira 티켓을 생성하고, PR 머지 시 상태를 `Done`으로 자동 전환합니다.
6. **💬 실시간 알림**: Discord Webhook을 통해 팀에 실시간으로 보안 이벤트를 알립니다.

> **핵심 가치**: 개발자는 보안 전문 지식 없이도, 코드를 Push하는 것만으로 자동으로 보안 취약점이 발견·수정·배포되는 **"Self-Healing" 개발 환경**을 경험할 수 있습니다.

---

## 🏗️ 시스템 아키텍처

### 전체 파이프라인 흐름도

```
GitHub Push Event
       │
       ▼
┌─────────────────────────────────────────────┐
│  GithubWebhookController                    │
│  (POST /api/webhook/github)                 │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  SecurityOrchestrator                       │
│  ┌───────────────────────────────────────┐  │
│  │ Step 1: Jira 티켓 생성 (분석 중)      │  │
│  │         → 즉시 202 Accepted 반환      │  │
│  └──────────────┬────────────────────────┘  │
│                 │ @Async (비동기)            │
│  ┌──────────────▼────────────────────────┐  │
│  │ Step 2: 병렬 스캔 실행                │  │
│  │  ├─ SnykCliScanner (SAST)             │  │
│  │  ├─ AzureDetectionService (CSPM)      │  │
│  │  └─ GenericApiScanner (동적 플러그인)  │  │
│  └──────────────┬────────────────────────┘  │
│                 │                            │
│  ┌──────────────▼────────────────────────┐  │
│  │ Step 3: AI 분석 및 코드 수정          │  │
│  │  ├─ CodeSanitizer (민감정보 마스킹)   │  │
│  │  ├─ AiManager → Gemini/GPT 호출       │  │
│  │  ├─ SandboxValidator (AST 위험 탐지)  │  │
│  │  └─ CodeValidatorService (컴파일 검증) │  │
│  └──────────────┬────────────────────────┘  │
│                 │                            │
│  ┌──────────────▼────────────────────────┐  │
│  │ Step 4: 결과 반영                     │  │
│  │  ├─ GitHub PR 자동 생성               │  │
│  │  ├─ Jira 티켓 업데이트                │  │
│  │  └─ Discord 실시간 알림               │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

### 레이어 구조

| 레이어 | 구성 요소 | 역할 |
|---|---|---|
| **Presentation** | `WebhookController`, `ConfigController`, `AuthController`, `DashboardController` | REST API 엔드포인트, JWT 인증 |
| **Orchestration** | `SecurityOrchestrator`, `DeduplicationService` | 파이프라인 조율, 중복 방지 |
| **Scanner** | `ScannerManager`, `SnykCliScanner`, `AzureDetectionService`, `GenericApiScanner` | 다중 스캐너 병렬 실행 및 결과 통합 |
| **AI** | `AiManager`, `OpenAiCompatibleAdapter`, `CodeSanitizer`, `SandboxValidator` | AI 패치 생성 및 3중 안전 검증 |
| **Infrastructure** | `GithubService`, `JiraService`, `DiscordNotificationService`, `EncryptionService` | 외부 서비스 연동, AES-GCM 암호화 |
| **Persistence** | `PostgreSQL` + `Flyway V1~V4` | DB 스키마 형상관리, 감사 로그 |

---

## 🧰 기술 스택

| 영역 | 기술 |
|---|---|
| **Language** | Java 21 |
| **Backend Framework** | Spring Boot 3.4, Spring WebFlux (비동기), Spring Security |
| **Database** | PostgreSQL (Supabase), Flyway Migration |
| **Authentication** | JWT (JSON Web Token) |
| **AI Engine** | Google Gemini API (OpenAI 호환 프로토콜) |
| **Security Scanner** | Snyk REST API (SAST), Azure SDK (CSPM) |
| **External Services** | GitHub REST API, Jira Cloud REST API, Discord Webhook |
| **Code Safety** | JavaParser (AST 분석), AES/GCM/NoPadding 암호화 |
| **Build Tool** | Gradle 9.3 |
| **CI/CD** | GitHub Actions |
| **Frontend** | Next.js (React), Vercel 배포 |
| **API Docs** | SpringDoc OpenAPI (Swagger UI) |

---

## ✨ 주요 기능

### 🔌 플러그인 아키텍처 (확장성)
- **내장(Static) 플러그인**: Snyk, Gemini AI, Azure — 환경 변수만 설정하면 즉시 사용.
- **동적(Dynamic) 플러그인**: 프론트엔드 Settings 화면에서 SonarQube, GPT-4o 등 어떤 REST API든 코드 수정 없이 등록 가능.
- **`USE_STATIC_PLUGINS` 토글**: `false`로 설정하면 내장 플러그인을 비활성화하고, UI에서 등록한 플러그인만 작동.

### 🤖 AI 자동 수정 + 3중 안전장치
1. **`CodeSanitizer`**: AI에게 보내기 전 API Key, 비밀번호 등 민감정보를 자동 마스킹. AI 응답에서도 민감정보 재검출.
2. **`SandboxValidator`**: AI가 생성한 코드를 AST(추상 구문 트리)로 파싱하여 `Runtime.exec()`, `ProcessBuilder` 등 위험 패턴을 사전 차단.
3. **`CodeValidatorService`**: 수정된 코드가 실제로 컴파일 가능한지 사전 검증. 실패 시 PR을 생성하지 않고 Jira 코멘트로만 기록.

### 🎫 Jira 자동 상태 관리
- **Push 이벤트** → Jira 티켓 자동 생성 (상태: `분석 중`)
- **스캔 완료** → 티켓에 취약점 상세 정보 코멘트 추가 (상태: `In Progress`)
- **PR 머지** → PR 본문에서 Jira 키를 파싱하여 자동으로 `Done` 상태 전환

### ☁️ 클라우드 인프라 보안 (CSPM)
- **Azure Storage Account** Public Access 감지 및 자동 잠금.
- SAST(코드 취약점)와 CSPM(인프라 취약점)을 하나의 파이프라인에서 통합 관리.

### 🔄 중복 방지 & Anti-Abuse
- **`DeduplicationService`**: 동일 취약점에 대한 중복 PR/티켓 생성 방지.
- **GitHub Anti-Abuse**: PR 연속 생성 시 15초 딜레이를 삽입하여 봇 계정 정지 방지.

---

## 📁 프로젝트 구조

```
src/main/java/com/example/autohealing/
├── ai/                         # AI 관련 로직
│   ├── AiManager.java              # 정적+동적 AI 엔진 관리 및 선택
│   ├── AiRemediationService.java   # AI 엔진 공통 인터페이스
│   ├── OpenAiCompatibleAdapter.java # Gemini/GPT 호환 어댑터
│   ├── CodeSanitizer.java          # 민감정보 마스킹 (입출력)
│   └── GeminiAiServiceImpl.java    # Gemini 전용 구현체
│
├── client/                     # 외부 스캐너 클라이언트
│   ├── ScannerManager.java         # 스캐너 병렬 실행 + 결과 취합
│   ├── SecurityScannerService.java # 스캐너 공통 인터페이스
│   ├── SnykClient.java             # Snyk REST API 클라이언트
│   ├── SnykCliScannerService.java  # Snyk 내장 스캐너 구현체
│   └── GenericApiScanner.java      # 동적 REST API 스캐너
│
├── config/                     # 설정 및 보안
│   ├── security/
│   │   ├── SecurityConfig.java     # Spring Security 설정 (CORS, CSRF, JWT)
│   │   ├── JwtProvider.java        # JWT 토큰 생성/검증
│   │   └── JwtAuthFilter.java      # JWT 인증 필터
│   └── AsyncConfig.java           # @Async 스레드 풀 설정
│
├── controller/                 # REST API 컨트롤러
│   ├── GithubWebhookController.java # GitHub Webhook 수신 (WebFlux 비동기)
│   ├── ConfigController.java       # 플러그인 CRUD API
│   ├── AuthController.java         # JWT 로그인 API
│   └── DashboardController.java    # 대시보드 데이터 API
│
├── orchestrator/               # 핵심 오케스트레이션
│   └── SecurityOrchestrator.java   # 전체 파이프라인 조율 엔진
│
├── service/                    # 비즈니스 서비스
│   ├── GithubService.java         # GitHub API (소스 읽기/PR 생성)
│   ├── JiraService.java           # Jira API (티켓 CRUD/상태 전환)
│   ├── DiscordNotificationService.java # Discord 알림
│   ├── AzureDetectionService.java # Azure CSPM 스캐너
│   ├── EncryptionService.java     # AES/GCM/NoPadding 암호화
│   ├── DeduplicationService.java  # 중복 취약점 방지
│   ├── CodeValidatorService.java  # AI 코드 컴파일 검증
│   └── SandboxValidator.java      # AST 기반 위험 패턴 탐지
│
├── parser/                     # 스캐너 결과 파서
│   ├── dto/UnifiedIssue.java      # 통합 취약점 DTO
│   └── snyk/SnykParserImpl.java   # Snyk JSON 응답 파서
│
├── entity/                     # JPA 엔티티
│   ├── SecurityLog.java           # 보안 로그 + 감사 필드
│   └── PluginConfig.java          # 플러그인 설정 (암호화 저장)
│
└── scheduler/
    └── SecurityScheduler.java     # 주기적 보안 스캔 스케줄러
```

---

## 🚀 실행 방법

### 사전 준비
- **Java 21** 이상
- **PostgreSQL** 데이터베이스 (또는 Supabase 등 클라우드 PostgreSQL)
- **Gradle 9.x** (프로젝트에 포함된 `gradlew` 사용 가능)

### 1. 저장소 클론
```bash
git clone https://github.com/sy7code/autohealing.git
cd autohealing
```

### 2. 환경 변수 설정
루트 디렉토리에 `.env` 파일을 생성하고, 아래 [환경 변수](#-환경-변수) 섹션을 참고하여 필요한 값들을 설정합니다.

### 3. 빌드
```bash
# 테스트 제외 빌드 (빠른 컴파일 확인)
./gradlew build -x test

# 전체 테스트 포함 빌드
./gradlew build
```

### 4. 실행
```bash
# Spring Boot 서버 실행 (기본 포트: 8080)
./gradlew bootRun
```

### 5. API 문서 확인
서버 실행 후 브라우저에서 Swagger UI에 접속합니다:
```
http://localhost:8080/swagger-ui/index.html
```

### 6. GitHub Webhook 연동
GitHub 저장소 Settings → Webhooks에서 다음을 설정합니다:
- **Payload URL**: `https://<server-domain>/api/webhook/github`
- **Content type**: `application/json`
- **Events**: `push`, `pull_request`

---

## 🔑 환경 변수

### 필수 (서버 기동용)

| 변수 | 설명 | 기본값 |
|---|---|---|
| `DB_URL` | PostgreSQL 접속 URL | `jdbc:postgresql://localhost:5432/autohealing` |
| `DB_USERNAME` | DB 사용자명 | `postgres` |
| `DB_PASSWORD` | DB 비밀번호 | `postgres` |
| `JWT_SECRET` | JWT 서명 키 (32자 이상) | 내장 기본값 |
| `ADMIN_USERNAME` | 대시보드 로그인 ID | `admin` |
| `ADMIN_PASSWORD` | 대시보드 로그인 PW | `password123` |
| `PLUGIN_ENCRYPTION_KEY` | API Key 암호화 시드 (16/24/32자) | 내장 기본값 |

### 필수 (핵심 기능용)

| 변수 | 설명 |
|---|---|
| `GITHUB_TOKEN` | GitHub Personal Access Token |
| `GITHUB_REPO` | 대상 저장소 (예: `sy7code/autohealing`) |
| `GITHUB_BASE_BRANCH` | PR 생성 시 기준 브랜치 (예: `develop`) |
| `SNYK_API_TOKEN` | Snyk API 인증 토큰 |
| `SNYK_ORG_ID` | Snyk Organization ID |
| `GEMINI_API_KEY` | Google Gemini API Key |

### 선택 (없어도 서버는 작동, 해당 기능만 비활성화)

| 변수 | 설명 |
|---|---|
| `JIRA_HOST` / `JIRA_EMAIL` / `JIRA_API_TOKEN` / `JIRA_PROJECT_KEY` | Jira 연동 |
| `DISCORD_WEBHOOK_URL` | Discord 실시간 알림 |
| `AZURE_SUBSCRIPTION_ID` | Azure 인프라(CSPM) 스캔 |
| `USE_STATIC_PLUGINS` | `false` 설정 시 내장 플러그인 비활성화 (기본: `true`) |

---

## 📖 API 문서

| 엔드포인트 | Method | 설명 |
|---|---|---|
| `/api/auth/login` | POST | JWT 토큰 발급 (로그인) |
| `/api/webhook/github` | POST | GitHub Webhook 수신 → 파이프라인 트리거 |
| `/api/webhook/github/test` | POST | 로컬 테스트용 파이프라인 트리거 |
| `/api/config/scanners` | GET/POST | 스캐너 플러그인 목록 조회/등록 |
| `/api/config/scanners/{id}` | PUT/DELETE | 스캐너 플러그인 수정/삭제 |
| `/api/config/ai-engines` | GET/POST | AI 엔진 플러그인 목록 조회/등록 |
| `/api/config/ai-engines/{id}` | PUT/DELETE | AI 엔진 플러그인 수정/삭제 |
| `/api/config/test` | POST | 플러그인 연동 테스트 (저장 전 확인) |
| `/api/dashboard/**` | GET | 대시보드 데이터 (취약점 목록/상세) |
| `/swagger-ui/index.html` | GET | Swagger API 문서 |

> 🔒 인증이 필요한 엔드포인트는 `Authorization: Bearer <JWT_TOKEN>` 헤더를 포함해야 합니다.

---

## 📦 개발 단계별 구현 상세 (Phases)

### Phase 1~2: 다중 스캐너 레이어

**목표**: 코드 변경 없이 어떤 보안 스캐너든 연동할 수 있는 **플러그인 구조** 구축.

- `SecurityScannerService` 인터페이스를 정의하여 모든 스캐너가 `providerName()`과 `scan()`을 구현하도록 설계.
- `ScannerManager`가 정적(Snyk, Azure) + 동적(UI 등록) 스캐너를 **병렬 실행** 후 결과를 `UnifiedIssue` DTO로 통합.
- `GenericApiScanner`를 구현하여 DB 설정만으로 REST API 기반 스캐너(SonarQube 등)를 코드 수정 없이 연동 가능.

### Phase 3: 다중 AI 레이어

**목표**: AI 엔진도 스캐너와 동일한 **플러그인 방식**으로 확장 가능하게 설계.

- `AiRemediationService` 인터페이스 → `OpenAiCompatibleAdapter`(Gemini/GPT 호환).
- `AiManager`가 활성화된 AI 엔진을 자동 선택하여 취약점 코드 분석 및 패치 코드 생성.
- `CodeSanitizer`로 AI 입출력의 민감정보(API Key, 비밀번호 등)를 자동 마스킹하는 보안 레이어 적용.

### Phase 4~5: 오케스트레이션 코어 & 안전장치

**목표**: 스캔 → AI 수정 → 검증 → PR 생성 → Jira 관리까지의 **전체 파이프라인 자동화**.

- `SecurityOrchestrator`가 전체 흐름을 조율. WebFlux `Mono.fromCallable` + `boundedElastic` 스레드 풀로 비동기 처리.
- AI 코드 안전성 3중 검증: `CodeSanitizer` → `SandboxValidator`(AST) → `CodeValidatorService`(컴파일).
- `DeduplicationService`로 동일 취약점 중복 PR/티켓 방지.
- GitHub PR 연속 생성 시 `15초 딜레이`를 삽입하여 봇 계정 Anti-Abuse 정책 준수.

### Phase 6: 설정 관리 REST API

**목표**: 프론트엔드에서 스캐너와 AI 엔진을 **코드 수정 없이 동적으로 등록/관리**할 수 있는 API 제공.

- `ConfigController`로 스캐너/AI 엔진 CRUD 엔드포인트 구현 (`/api/config/scanners`, `/api/config/ai-engines`).
- API Key 보안: 저장 시 AES 암호화, 조회 시 자동 마스킹(`sk-12****cdef`), 수정 시 마스킹된 값 무시 로직.

### Phase 7: 백엔드 안정화 & 긴급 수정

**목표**: 실제 운영 환경에서 발생할 수 있는 **엣지 케이스 방어 및 테스트 안정화**.

- Spring Security CSRF 설정 최적화 (JWT 기반 Stateless API에 맞게 조정).
- Phase 8 변경으로 깨진 4개 테스트 케이스 전부 수정 (총 39개 테스트 PASS).
- `EncryptionService` 복호화 실패 시 서버 크래시 방지 (`[DECRYPTION_FAILED]` 반환으로 격리).

### Phase 8: 자립형 백엔드 (Self-Contained)

**목표**: 내장 플러그인 없이도 UI 등록 플러그인만으로 **독립 작동 가능한 구조** 구현.

- `USE_STATIC_PLUGINS` 토글 추가: `false` 설정 시 내장 Snyk/Gemini를 비활성화하고 동적 플러그인만 작동.
- `POST /api/config/test` 연동 테스트 API: 플러그인 저장 전 실제 API 호출하여 연동 가능 여부 사전 확인.
- URL 동적 변수 치환 (`${org_id}` → 실제 값) 및 커스텀 파라미터 지원.
- Flyway `V4` 마이그레이션: `custom_params_json` 컬럼 추가.

### Phase 9: 프론트엔드 연동 (대시보드)

**목표**: 보안 취약점 현황을 **시각적으로 모니터링**할 수 있는 대시보드 API 구성.

- `DashboardController`를 통한 취약점 목록/상세 조회 API.
- SAST(코드 취약점)와 CSPM(인프라 취약점)을 탭으로 분리하여 한 눈에 파악.
- Next.js 프론트엔드와의 연동: JWT 인증 → API 호출 → 데이터 시각화.

### Phase 10: Azure 인프라 스캐너 통합 & 보안 강화

**목표**: 클라우드 인프라 보안(CSPM)을 코어 파이프라인에 통합하고, **Snyk 보안 감사 전면 대응**.

- `AzureDetectionService`에 `SecurityScannerService` 인터페이스를 구현하여 SAST + CSPM 통합.
- Snyk 보안 감사 전면 대응:
  - CSRF 오탐 방어: `AuthController`, `GithubWebhookController`, `ConfigController`에 DeepCode ignore 적용.
  - 의존성 취약점 해결: `jackson-core` 2.18.6, `azure-resourcemanager` 2.42.0, `azure-identity` 1.18.1 등으로 업데이트.
  - `EncryptionService`를 AES/ECB → **AES/GCM/NoPadding**으로 마이그레이션 (CWE-327 해결).

---

## 🔐 보안 고려 사항

| 항목 | 구현 |
|---|---|
| **인증** | JWT 토큰 기반 Stateless 인증 (Spring Security) |
| **암호화** | AES/GCM/NoPadding (12바이트 IV + 128비트 태그) |
| **API Key 보호** | 저장 시 암호화, 조회 시 마스킹, 수정 시 마스킹 값 무시 |
| **AI 입출력 보안** | `CodeSanitizer`로 민감정보 자동 마스킹 |
| **AI 코드 안전성** | AST 분석(위험 패턴 차단) + 컴파일 검증(실패 시 PR 미생성) |
| **CSRF** | Stateless JWT API이므로 세션 기반 CSRF 공격 불가능 |
| **CORS** | 프론트엔드 도메인만 허용하는 화이트리스트 방식 |
| **의존성 관리** | Snyk 정기 스캔 + 취약 라이브러리 즉시 업데이트 정책 |
| **Anti-Abuse** | GitHub PR 연속 생성 시 15초 딜레이 삽입 |

---

<p align="center">
  <strong>Built with ❤️ for DevSecOps Automation</strong>
</p>
