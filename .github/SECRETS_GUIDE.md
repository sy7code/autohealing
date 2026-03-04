# GitHub Secrets 설정 가이드

CD 워크플로우(`cd.yml`) 실행을 위해 GitHub 저장소의 **Settings → Secrets and variables → Actions**에서 아래 시크릿을 등록해야 합니다.

## 필수 Secrets 목록

| Secret 이름 | 설명 | 예시 / 획득 방법 |
| :--- | :--- | :--- |
| `AZURE_WEBAPP_NAME` | Azure App Service 앱 이름 | `autohealing-backend` |
| `AZURE_WEBAPP_PUBLISH_PROFILE` | Azure App Service 퍼블리시 프로파일 XML 전체 | Azure Portal → App Service → 개요 → 게시 프로필 다운로드 |
| `DB_URL` | Supabase PostgreSQL JDBC URL | `jdbc:postgresql://db.xxx.supabase.co:5432/postgres` |
| `DB_USERNAME` | DB 사용자명 | `postgres` |
| `DB_PASSWORD` | DB 비밀번호 | Supabase 프로젝트 설정에서 확인 |
| `JIRA_HOST` | Jira Cloud 도메인 | `https://your-domain.atlassian.net` |
| `JIRA_EMAIL` | Jira 계정 이메일 | `your@email.com` |
| `JIRA_API_TOKEN` | Jira API 토큰 | https://id.atlassian.com/manage-profile/security/api-tokens |
| `JIRA_PROJECT_KEY` | Jira 프로젝트 키 | `SCRUM` |
| `DISCORD_WEBHOOK_URL` | Discord Webhook URL | Discord 채널 설정 → 연동 → 웹후크 |
| `JWT_SECRET` | JWT 서명 시크릿 (32자 이상) | 랜덤 문자열 생성: `openssl rand -base64 48` |
| `ADMIN_USERNAME` | 대시보드 관리자 아이디 | `admin` |
| `ADMIN_PASSWORD` | 대시보드 관리자 비밀번호 | 안전한 비밀번호 설정 |
| `GEMINI_API_KEY` | Gemini AI API 키 | https://aistudio.google.com/app/apikey |
| `SNYK_TOKEN` | Snyk CLI 인증 토큰 | `snyk config get api` 또는 Snyk 계정 설정 |
| `AZURE_SUBSCRIPTION_ID` | Azure 구독 ID | Azure Portal → 구독에서 확인 |
| `LOCAL_REPO_PATH` | App Service 내 스캔 대상 레포 경로 | `/home/site/wwwroot/repo` |
| `VERCEL_URL` | 프론트엔드 Vercel 배포 URL | `https://your-app.vercel.app` |

## 퍼블리시 프로파일 획득 방법

1. Azure Portal 접속
2. 해당 App Service 리소스 선택
3. 상단 메뉴 **"게시 프로필 다운로드"** 클릭
4. 다운로드된 `.PublishSettings` 파일의 **전체 XML 내용**을 `AZURE_WEBAPP_PUBLISH_PROFILE` 시크릿 값으로 등록

## App Service 환경변수 설정

App Service의 **설정 → 환경 변수**에도 아래 값들을 추가해야 합니다.
(GitHub Actions CD는 JAR만 배포하며, 런타임 환경변수는 App Service에서 직접 관리합니다.)

```
SPRING_PROFILES_ACTIVE=prod
DB_URL=<Supabase JDBC URL>
DB_USERNAME=<DB 사용자명>
DB_PASSWORD=<DB 비밀번호>
JIRA_HOST=<Jira URL>
JIRA_EMAIL=<Jira 이메일>
JIRA_API_TOKEN=<Jira 토큰>
JIRA_PROJECT_KEY=<프로젝트 키>
DISCORD_WEBHOOK_URL=<Discord Webhook URL>
JWT_SECRET=<JWT 시크릿>
ADMIN_USERNAME=<관리자 ID>
ADMIN_PASSWORD=<관리자 PW>
GEMINI_API_KEY=<Gemini API 키>
SNYK_TOKEN=<Snyk 토큰>
AZURE_SUBSCRIPTION_ID=<구독 ID>
LOCAL_REPO_PATH=<스캔 경로>
VERCEL_URL=<Vercel URL>
```
