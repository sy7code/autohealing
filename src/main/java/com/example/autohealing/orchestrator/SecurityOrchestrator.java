package com.example.autohealing.orchestrator;

import com.example.autohealing.ai.AiManager;
import com.example.autohealing.ai.AiRemediationResult;
import com.example.autohealing.ai.CodeSanitizer;
import com.example.autohealing.client.ScannerManager;
import com.example.autohealing.parser.snyk.SnykParserImpl;
import com.example.autohealing.entity.SecurityLog;
import com.example.autohealing.repository.SecurityLogRepository;
import com.example.autohealing.parser.dto.UnifiedIssue;
import com.example.autohealing.service.JiraService;
import com.example.autohealing.service.CodeValidatorService;
import com.example.autohealing.service.DiscordNotificationService;
import com.example.autohealing.service.GithubService;
import com.example.autohealing.config.JiraConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import com.example.autohealing.common.ScannerConstants;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * GitHub Webhook 수신 후 2단계 보안 분석 + AI 자동 수정을 오케스트레이션하는 서비스.
 *
 * <pre>
 * ┌─ Step 1 (동기) ─────────────────────────────────────────┐
 * │ 웹훅 수신 즉시 "보안 분석 중" Jira 티켓 생성 → issueKey  │
 * └──────────────────────────────────────────────────────────┘
 *                        ↓ 202 반환
 * ┌─ Step 2 (@Async, securityTaskExecutor) ─────────────────┐
 * │ A. Snyk CLI 스캔 (snyk test --json)                      │
 * │ B. UnifiedIssue 파싱 (SnykCliScannerService 내부 처리)   │
 * │ C. CRITICAL/HIGH 취약점별 AI 자동 수정 시도 + 컴파일 검증 │
 * │ D. Jira 티켓 최종 업데이트 + 개별 티켓 생성               │
 * └──────────────────────────────────────────────────────────┘
 * </pre>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityOrchestrator {

  private final JiraService jiraService;
  private final ScannerManager scannerManager;
  private final SnykParserImpl snykParser;
  private final AiManager aiManager;
  private final GithubService githubService;
  private final CodeValidatorService codeValidatorService;
  private final SecurityLogRepository securityLogRepository;
  private final JiraConfig jiraConfig;
  private final DiscordNotificationService discordNotificationService;
  private final CodeSanitizer codeSanitizer;
  private final com.example.autohealing.service.DeduplicationService deduplicationService;

  @Value("${VERCEL_URL:http://localhost:3000}")
  private String vercelUrl;

  // ─────────────────────────────────────────────────────────────────────────
  // Step 1: 즉시 응답용 "분석 중" 티켓 생성 (동기)
  // ─────────────────────────────────────────────────────────────────────────

  // ─────────────────────────────────────────────────────────────────────────
  // Step 1: 즉시 응답용 "분석 중" 티켓 생성 (동기)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * GitHub Webhook 수신 직후 보안 분석이 시작되었음을 알리는 Jira 티켓을 생성합니다.
   * 이 작업은 동기적으로 처리되어 웹훅에 빠르게 응답(202 Accepted)할 수 있도록 합니다.
   *
   * @param repoName  분석 대상 저장소 이름
   * @param commitId  스캔 대상 커밋 ID
   * @param committer 커밋 작성자
   * @return 생성된 Jira 티켓의 Key (예: SCRUM-42)
   */
  public String startAnalysis(String repoName, String commitId, String committer) {
    log.info("[Orchestrator] 보안 분석 시작 - repo={}, commit={}", repoName, commitId);

    String summary = String.format("[보안 분석 중] %s - 커밋 %s", repoName, commitId);
    String description = String.format("""
        🔍 GitHub 커밋 감지 - 보안 스캔을 시작합니다.
        ──────────────────────────────
        저장소  : %s
        커밋 ID : %s
        작성자  : %s
        스캐너  : Snyk REST API
        AI 엔진 : %s
        ──────────────────────────────
        ⏳ 통합 보안 스캐너 분석이 백그라운드에서 실행 중입니다.
        분석 완료 후 이 티켓이 자동으로 업데이트됩니다.
        """, repoName, commitId, committer, aiManager.getActiveAi().providerName());

    return jiraService.createIssue(summary, description);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Step 2: 비동기 Snyk CLI 스캔 + AI 수정 + Jira 업데이트
  // ─────────────────────────────────────────────────────────────────────────

  // ─────────────────────────────────────────────────────────────────────────
  // Step 2: 비동기 Snyk CLI 스캔 + AI 수정 + Jira 업데이트
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * 백그라운드에서 ScannerManager를 통해 통합 보안 스캔을 실행하고, 위험도가 높은 취약점에 대해 AI 수정을 시도합니다.
   * 처리 후 기존에 생성된 "분석 중" Jira 티켓을 최종 결과로 업데이트합니다.
   *
   * @param issueKey 원본 "분석 중" Jira 티켓 Key
   * @param repoName 저장소 이름
   */
  @Async("securityTaskExecutor")
  public void runScanAndUpdate(String issueKey, String repoName) {
    log.info("[Orchestrator][Async] Step2 시작 - issueKey={}, repo={}, aiEngine={}",
        issueKey, repoName, aiManager.getActiveAi().providerName());

    try {
      // A. 다중 모듈 스캔 연동 (ScannerManager)
      log.info("[Orchestrator][Async] 스캐너 매니저를 통해 취약점 통합 수집 중...");
      List<Map<String, Object>> rawIssues = scannerManager.runAllActiveScanners(repoName);
      log.info("[Orchestrator][Async] rawIssues 수신: {}건", rawIssues.size());

      // 디버그: rawIssues 내용 출력
      for (int idx = 0; idx < rawIssues.size(); idx++) {
        Map<String, Object> raw = rawIssues.get(idx);
        log.info("[Orchestrator][Async] rawIssue[{}]: id={}, severity={}, title={}, scannerName={}",
            idx, raw.get("id"), raw.get("severity"), raw.get("title"), raw.get("scannerName"));
      }

      // UnifiedIssue 변환 (개별 예외 방어)
      List<UnifiedIssue> issues = new ArrayList<>();
      for (Map<String, Object> raw : rawIssues) {
        try {
          UnifiedIssue issue = snykParser.toUnifiedIssue(raw);
          issues.add(issue);
          log.info("[Orchestrator][Async] UnifiedIssue 변환 성공: id={}, severity={}, source={}, filePath={}",
              issue.getId(), issue.getSeverity(), issue.getSource(), issue.getFilePath());
        } catch (Exception e) {
          log.error("[Orchestrator][Async] UnifiedIssue 변환 실패: raw={}", raw, e);
        }
      }
      log.info("[Orchestrator][Async] 통합 스캔 완료 - 취약점 {}건 (rawIssues {}건 중)", issues.size(), rawIssues.size());

      if (issues.isEmpty()) {
        updateWithNoIssues(issueKey, repoName);
        return;
      }

      // B. CRITICAL/HIGH → AI 자동 수정 + 컴파일 검증
      java.util.Set<String> aiFixedIds = applyAiRemediation(issueKey, repoName, issues);

      // C. Jira 최종 업데이트
      updateWithVulnerabilities(issueKey, repoName, issues, aiFixedIds);

    } catch (Exception e) {
      log.error("[Orchestrator][Async] 오류 발생 - issueKey={}", issueKey, e);
      jiraService.updateIssue(issueKey,
          "[보안 분석 실패] " + repoName,
          "보안 분석 중 오류: " + e.getMessage());
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – AI 수정 + 컴파일 검증
  // ─────────────────────────────────────────────────────────────────────────

  // ─────────────────────────────────────────────────────────────────────────
  // Private – AI 수정 + 컴파일 검증
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Snyk 스캔 결과 중 CRITICAL 및 HIGH 등급의 취약점만 필터링하여 AI 기반 자동 수정을 시도합니다.
   * 수정된 코드는 컴파일 검증을 거치며, 개별 취약점마다 상세 Jira 티켓과 (성공 시) GitHub PR을 생성합니다.
   *
   * @param issueKey 원본 "분석 중" Jira 티켓 Key (컴파일 오류 등 코멘트 등록용)
   * @param repoName 대상 저장소
   * @param issues   Snyk 스캔으로 발견된 취약점 목록
   * @return AI가 성공적으로 수정 및 컴파일 검증까지 마친 취약점들의 Snyk ID Set
   */
  private java.util.Set<String> applyAiRemediation(String issueKey, String repoName, List<UnifiedIssue> issues) {
    java.util.Set<String> fixedIds = new java.util.HashSet<>();

    log.info("[Orchestrator][Diagnostic] 전체 이슈 목록 ({}건):", issues.size());
    for (UnifiedIssue i : issues) {
      log.info(" - ID: {}, Severity: {}, Source: {}, Title: {}", i.getId(), i.getSeverity(), i.getSource(), i.getTitle());
    }

    List<UnifiedIssue> targets = issues.stream()
        .filter(i -> i.getSeverity() == UnifiedIssue.SeverityLevel.CRITICAL
            || i.getSeverity() == UnifiedIssue.SeverityLevel.HIGH)
        .toList();

    java.util.Set<String> processedIds = new java.util.HashSet<>();

    log.info("[Orchestrator][AI] CRITICAL/HIGH 필터링 결과: {}건 AI 수정 도 및 티켓 생성 (원래 {}건)", targets.size(), issues.size());

    for (UnifiedIssue issue : targets) {
      if (!processedIds.add(issue.getId())) {
        continue;
      }

      boolean isFixed = processSingleVulnerability(issueKey, repoName, issue);
      if (isFixed) {
        fixedIds.add(issue.getId());
      }
    }
    return fixedIds;
  }

  private boolean processSingleVulnerability(String parentIssueKey, String repoName, UnifiedIssue issue) {
    log.info("[Orchestrator][Diagnostic] 개별 취약점 처리 시작 - ID: {}", issue.getId());
    if (deduplicationService.shouldSkip(issue)) {
      log.warn("[Orchestrator][Diagnostic] 중복(Regression 방어 및 어뷰징 방지)으로 인 해당 취약점 처리를 스킵합니다. ID={}", issue.getId());
      return false;
    }

    // v10: 인프라 취약점은 AI 수정을 건너뛰고 수동 리뷰 상태로 바로 저장 (CSPM 분리)
    if (!ScannerConstants.SOURCE_SNYK.equals(issue.getSource())) {
      log.warn("[Orchestrator][Diagnostic] 인프라 스캐너({})에서 발견된 이슈이므로 AI 자동 수정을 건너뛰고 수동 리뷰용 알림만 생성합니다. ID={}", issue.getSource(), issue.getId());
      createTicketsAndPrs(repoName, issue, null, null, "인프라(CSPM) 취약점이므로 수동 설정 변경(Manual Review)이 필요합니다.", false);
      return false;
    }


    boolean isAiFixed = false;
    String fixedCode = "";
    String explanation = "";
    String originalCode = "";

    try {
      // v18 방어: 파일 경로 불일치(404) 대응 - 중단하지 않고 스킵
      try {
        originalCode = readSourceFile(repoName, issue);
      } catch (Exception e) {
        log.warn("[Orchestrator] 파일 경로 불일치로 AI 수정 스킵: {}", issue.getFilePath());

        SecurityLog securityLog = new SecurityLog(repoName, issue.getTitle(), issue.getSeverity().name(),
            "SKIPPED_FILE_NOT_FOUND");
        securityLog.setVulnId(issue.getId());
        securityLogRepository.save(securityLog);
        return false;
      }

      // "// 소스코드" 등으로 시작하는 에러 메시지가 리턴된 경우
      if (originalCode.startsWith("//")) {
        log.warn("[Orchestrator] 소스 코드를 읽어올 수 없어 스킵: {}", issue.getFilePath());
        return false;
      }

      // v18 방어: 무료 티어 AI 출력 토큰 한계(Truncation) 방어로초대형 파일 파괴 방지
      if (originalCode.length() > 30000) {
        log.warn("[Orchestrator] 파일이 너무 커서 AI 무료 티어 출력 한계를 초과합니다 (3만자 이상). 안전을 위해 스킵: {}", issue.getFilePath());
        SecurityLog securityLog = new SecurityLog(repoName, issue.getTitle(), issue.getSeverity().name(),
            "SKIPPED_TOO_LARGE");
        securityLog.setVulnId(issue.getId());
        securityLogRepository.save(securityLog);
        return false;
      }

      String vulnInfo = buildVulnerabilityInfo(issue);

      // v16 1차 방어: 민감 정보 마스킹 (Sanitization)
      String sanitizedInput = codeSanitizer.sanitizeInput(originalCode);

      AiRemediationResult result = aiManager.getActiveAi().fixCode(sanitizedInput, vulnInfo);
      fixedCode = result.getFixedCode();
      explanation = result.getExplanation();

      // v16 2차 방어: AI 수정 코드에 민감정보가 유출되었는지(환각 등) 강제 검사
      if (codeSanitizer.containsSensitiveData(fixedCode)) {
        log.warn("[Orchestrator] ⚠️ AI 수정 코드에 민감정보 탐지! PR 생성 차단됨 - vulnId={}", issue.getId());
        SecurityLog securityLog = new SecurityLog(repoName, issue.getTitle(), issue.getSeverity().name(),
            "BLOCKED_SENSITIVE_DATA");
        securityLog.setVulnId(issue.getId());
        securityLogRepository.save(securityLog);
        return false;
      }

      log.info("[Orchestrator][AI] 수정 완료 - id={} ({}자→{}자)",
          issue.getId(), originalCode.length(), fixedCode.length());

      String fileName = extractFilePath(issue.getDescription());
      if (fileName == null)
        fileName = "Unknown.java";

      String compileError = codeValidatorService.validateCode(fixedCode, fileName);

      if (compileError != null) {
        log.warn("[Orchestrator][AI] 컴파일 검증 실패 - id={}, error=\n{}", issue.getId(), compileError);
        jiraService.addCommentToIssue(parentIssueKey,
            "🚨 **AI 수정안 컴파일 오류 발생**\n" +
                "AI가 생성한 수정 코드가 컴파일되지 않아 PR 생성을 중단했습니다.\n" +
                "**파일:** `" + fileName + "`\n" +
                "**에러 내용:**\n{code:java}\n" + compileError + "\n{code}");
      } else {
        isAiFixed = true;
      }
    } catch (Exception e) {
      log.warn("[Orchestrator][AI] 수정 실패 - id={}", issue.getId(), e);
      explanation = "AI 자동 수정 중 오류 발생: " + e.getMessage();
    }

    if (isAiFixed) {
      // v18 방어: Github Anti-Abuse Rate Limit (Secondary Limit) 방어
      // 로봇이 10초 만에 50개의 PR을 연속으로 생성하면 봇 계정이 영구 정지됩니다. 15초 슬립으로 인간처럼 행동하게 만듭니다.
      try {
        log.info("[Orchestrator] 봇 계정 정지(Abuse) 방지를 위한 15초 대기 딜레이 진입...");
        Thread.sleep(15000);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }

    createTicketsAndPrs(repoName, issue, originalCode, fixedCode, explanation, isAiFixed);
    return isAiFixed;
  }

  private void createTicketsAndPrs(String repoName, UnifiedIssue issue, String originalCode, String fixedCode,
      String explanation, boolean isAiFixed) {
    SecurityLog securityLog = new SecurityLog(
        repoName,
        issue.getTitle(),
        issue.getSeverity().name(),
        isAiFixed ? "AI 패치 대기중" : "수동 리뷰 필요");
    securityLog.setVulnId(issue.getId());
    securityLog.setAiFixed(isAiFixed);
    securityLog.setOriginalCode(originalCode);
    securityLog.setPatchedCode(fixedCode);
    securityLog.setFixExplanation(explanation);
    securityLog = securityLogRepository.save(securityLog);
    log.info("[Orchestrator] DB 저장 완료 - dbId={}, snykId={}", securityLog.getId(), issue.getId());

    String dashboardDetailUrl = vercelUrl + "/detail/" + securityLog.getId();

    java.util.List<String> labels = new java.util.ArrayList<>();
    labels.add("Auto-Fix");
    if (isAiFixed) {
      labels.add("AI-Fixed");
      labels.add("Security-Patch");
    }

    String markdownDesc = String.format("""
        | 특성 | 세부 정보 |
        | :--- | :--- |
        | **취약점 ID** | %s |
        | **위험도**   | %s |
        | **패키지 경로**| %s |
        | **AI 자동수정**| %s |
        | **대시보드 링크**| [Vercel 상세보기 바로가기](%s) |

        ### 💡 상세 내용
        %s

        %s
        """,
        issue.getId(),
        issue.getSeverity().name(),
        extractFilePath(issue.getDescription()),
        isAiFixed ? "✅ 예 (Github PR 생성됨)" : "❌ 아니오",
        dashboardDetailUrl,
        issue.getDescription(),
        isAiFixed ? ("=== AI 자동 수정 내용 요약 ===\n" + explanation) : "");

    String jiraKey = jiraService.createIssue(
        issue.getTitle(), markdownDesc, issue.getSeverity().name(), labels);

    log.info("[Orchestrator][Async] 개별 티켓 생성: {} → {}", issue.getId(), jiraKey);

    if (jiraKey != null && issue.getSeverity() != null) {
      discordNotificationService.sendSnykAlert(
          issue.getTitle(),
          issue.getSeverity().name(),
          jiraConfig.getHost() + "/browse/" + jiraKey);
    }

    if (jiraKey != null) {
      securityLog.setJiraKey(jiraKey);
      securityLogRepository.save(securityLog);
    }

    if (isAiFixed) {
      if (jiraKey != null) {
        jiraService.transitionIssue(jiraKey, jiraConfig.getTransition().getInProgress());
        explanation += "\n\n**🔗 연동된 Jira 티켓:** " + jiraKey;
      }
      Integer prNumber = githubService.createPullRequest(repoName, issue, originalCode, fixedCode, explanation);
      if (prNumber != null) {
        securityLog.setPrNumber(prNumber);
        securityLogRepository.save(securityLog);

        String prUrl = "https://github.com/" + repoName + "/pull/" + prNumber;
        discordNotificationService.sendPrCreatedAlert(
            "fix/auto-fix-" + issue.getId().replaceAll("[^a-zA-Z0-9-]", "-"),
            prUrl,
            dashboardDetailUrl);
      }
    }
  }

  /**
   * 취약점 정보(description)에서 파일 경로를 추출해 서버(GitHub)에서 원본 소스코드를 가져옵니다.
   */
  private String readSourceFile(String repoName, UnifiedIssue issue) {
    String filePath = issue.getFilePath();
    if (filePath == null || filePath.equals("build.gradle")) {
       // filePath가 없거나 기본값일 경우, description에서 한 번 더 상세 추출 시도
       String extracted = extractFilePath(issue.getDescription());
       if (extracted != null) filePath = extracted;
    }

    // GitHub API를 통해 원격 코드를 가져옵니다
    String remoteCode = githubService.getFileContentAsString(repoName, filePath, null);
    if (remoteCode != null) {
      log.info("[Orchestrator][Remote] GitHub에서 파일 읽기 성공: {}", filePath);
      return remoteCode;
    }

    return "// 소스코드를 가져올 수 없습니다: " + filePath + "\n" + issue.getDescription();
  }

  private String buildVulnerabilityInfo(UnifiedIssue issue) {
    return String.format("ID: %s | 심각도: %s | 제목: %s\n%s",
        issue.getId(), issue.getSeverity(), issue.getTitle(), issue.getDescription());
  }

  private String extractFilePath(String description) {
    if (description == null)
      return null;
    for (String line : description.lines().toList()) {
      String lowerLine = line.toLowerCase();
      if (lowerLine.startsWith("패키지 경로") || lowerLine.startsWith("file") || lowerLine.startsWith("파일 경로")) {
        String[] parts = line.split(":", 2);
        if (parts.length == 2) {
          String path = parts[1].trim();
          // "build.gradle (log4j@2.17.1)" 같은 형식에서 파일명만 추출
          if (path.contains(" ")) {
            path = path.split(" ")[0];
          }
          return path;
        }
      }
    }
    // 의존성 취약점의 경우 기본적으로 build.gradle 리턴 (SnykParser 에서 이미 어느 정도 처리하지만 이중 방어)
    return "build.gradle";
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – Jira 업데이트
  // ─────────────────────────────────────────────────────────────────────────

  private void updateWithNoIssues(String issueKey, String repoName) {
    log.info("[Orchestrator][Async] 취약점 없음 - 티켓 업데이트: {}", issueKey);
    jiraService.updateIssue(
        issueKey,
        "[보안 분석 완료] " + repoName + " - 취약점 없음 ✅",
        "✅ Snyk 보안 분석 완료: 감지된 취약점이 없습니다.");
  }

  private void updateWithVulnerabilities(String issueKey, String repoName,
      List<UnifiedIssue> issues, java.util.Set<String> aiFixedIds) {
    int aiFixedCount = aiFixedIds.size();
    long critical = issues.stream()
        .filter(i -> i.getSeverity() == UnifiedIssue.SeverityLevel.CRITICAL).count();
    long high = issues.stream()
        .filter(i -> i.getSeverity() == UnifiedIssue.SeverityLevel.HIGH).count();

    String summary = String.format(
        "[보안 분석 완료] %s - 취약점 %d건 (C:%d/H:%d) | AI수정 %d건 ⚠️",
        repoName, issues.size(), critical, high, aiFixedCount);

    StringBuilder sb = new StringBuilder();
    sb.append(String.format("⚠️ 통합 보안 분석 완료: %d건 발견\n", issues.size()));
    sb.append(String.format("🤖 AI(%s) 자동 수정: %d건\n", aiManager.getActiveAi().providerName(), aiFixedCount));
    sb.append("──────────────────────────────\n");
    for (int i = 0; i < issues.size(); i++) {
      UnifiedIssue issue = issues.get(i);
      sb.append(String.format("[%d] [%s] %s\n    ID: %s\n\n",
          i + 1, issue.getSeverity(), issue.getTitle(), issue.getId()));
    }
    if (aiFixedCount > 0) {
      sb.append(String.format("🔧 %d건은 AI가 수정 코드를 생성했습니다.", aiFixedCount));
    }

    jiraService.updateIssue(issueKey, summary, sb.toString());
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Step 2 (variant): GitHub Actions Snyk CLI 결과 직접 처리
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * GitHub Actions에서 Snyk CLI 스캔 결과를 직접 수신하여 처리합니다.
   *
   * <p>Snyk 무료 플랜에서 REST API 403 제한을 우회하기 위해,
   * GitHub Actions에서 {@code snyk test --json} 결과를 서버로 POST하는 방식을 사용합니다.
   *
   * <h3>페이로드 구조</h3>
   * <pre>
   * {
   *   "repo": "org/repo",
   *   "commit": "abc1234",
   *   "committer": "username",
   *   "vulnerabilities": [  ← snyk test --json 의 vulnerabilities 배열
   *     { "id": "SNYK-JAVA-...", "title": "...", "severity": "high", ... }
   *   ]
   * }
   * </pre>
   *
   * @param issueKey Jira 초기 티켓 Key (이미 생성된 상태)
   * @param repoName 저장소 이름
   * @param payload  Snyk 스캔 결과 페이로드
   */
  @Async("securityTaskExecutor")
  public void processSnykPayload(String issueKey, String repoName, Map<String, Object> payload) {
    log.info("[Orchestrator][SnykPayload] Step2 시작 - issueKey={}, repo={}", issueKey, repoName);

    try {
      // payload에서 vulnerabilities 추출 (snyk test --json 구조와 동일)
      List<Map<String, Object>> rawIssues = extractVulnerabilities(payload);
      log.info("[Orchestrator][SnykPayload] rawIssues 수신: {}건", rawIssues.size());

      // 디버그: rawIssues 내용 출력
      for (int idx = 0; idx < Math.min(rawIssues.size(), 10); idx++) {
        Map<String, Object> raw = rawIssues.get(idx);
        log.info("[Orchestrator][SnykPayload] rawIssue[{}]: id={}, severity={}, title={}",
            idx, raw.get("id"), raw.get("severity"), raw.get("title"));
      }

      // UnifiedIssue 변환 (개별 예외 방어)
      List<UnifiedIssue> issues = new ArrayList<>();
      for (Map<String, Object> raw : rawIssues) {
        try {
          UnifiedIssue issue = snykParser.toUnifiedIssue(raw);
          issues.add(issue);
          log.info("[Orchestrator][SnykPayload] UnifiedIssue 변환 성공: id={}, severity={}, filePath={}",
              issue.getId(), issue.getSeverity(), issue.getFilePath());
        } catch (Exception e) {
          log.error("[Orchestrator][SnykPayload] UnifiedIssue 변환 실패: raw={}", raw, e);
        }
      }
      log.info("[Orchestrator][SnykPayload] 변환 완료 - {}건 (raw {}건 중)", issues.size(), rawIssues.size());

      if (issues.isEmpty()) {
        updateWithNoIssues(issueKey, repoName);
        return;
      }

      // CRITICAL/HIGH → AI 자동 수정 + 컴파일 검증
      java.util.Set<String> aiFixedIds = applyAiRemediation(issueKey, repoName, issues);

      // Jira 최종 업데이트
      updateWithVulnerabilities(issueKey, repoName, issues, aiFixedIds);

    } catch (Exception e) {
      log.error("[Orchestrator][SnykPayload] 오류 발생 - issueKey={}", issueKey, e);
      jiraService.updateIssue(issueKey,
          "[보안 분석 실패] " + repoName,
          "Snyk 페이로드 처리 중 오류: " + e.getMessage());
    }
  }

  /**
   * 페이로드에서 취약점 목록을 추출합니다.
   * snyk test --json 형식의 최상위 "vulnerabilities" 배열을 추출합니다.
   */
  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> extractVulnerabilities(Map<String, Object> payload) {
    Object vulnsObj = payload.get("vulnerabilities");
    if (vulnsObj instanceof List<?> list) {
      List<Map<String, Object>> result = new ArrayList<>();
      for (Object item : list) {
        if (item instanceof Map<?, ?> map) {
          result.add((Map<String, Object>) map);
        }
      }
      return result;
    }
    log.warn("[Orchestrator][SnykPayload] 'vulnerabilities' 키 없음 또는 형식 오류. 페이로드 키: {}", payload.keySet());
    return new ArrayList<>();
  }

  /**
   * PR Merge 이벤트 수신 시 티켓 상태를 Done으로 전환합니다.
   */
  public boolean completeJiraTicket(String jiraKey) {
    log.info("[Orchestrator] PR Merge 감지 - Jira 티켓 완료 처리: {}", jiraKey);
    return jiraService.transitionIssue(jiraKey, jiraConfig.getTransition().getDone());
  }
}
