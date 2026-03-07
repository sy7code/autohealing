package com.example.autohealing.orchestrator;

import com.example.autohealing.ai.AiRemediationService;
import com.example.autohealing.ai.AiRemediationResult;
import com.example.autohealing.client.SnykClient;
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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
  private final SnykClient snykClient;
  private final SnykParserImpl snykParser;
  private final AiRemediationService aiRemediationService;
  private final GithubService githubService;
  private final CodeValidatorService codeValidatorService;
  private final SecurityLogRepository securityLogRepository;
  private final JiraConfig jiraConfig;
  private final DiscordNotificationService discordNotificationService;

  @Value("${LOCAL_REPO_PATH:}")
  private String localRepoPath;

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
        ⏳ Snyk 보안 분석이 백그라운드에서 실행 중입니다.
        분석 완료 후 이 티켓이 자동으로 업데이트됩니다.
        """, repoName, commitId, committer, aiRemediationService.providerName());

    return jiraService.createIssue(summary, description);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Step 2: 비동기 Snyk CLI 스캔 + AI 수정 + Jira 업데이트
  // ─────────────────────────────────────────────────────────────────────────

  // ─────────────────────────────────────────────────────────────────────────
  // Step 2: 비동기 Snyk CLI 스캔 + AI 수정 + Jira 업데이트
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * 백그라운드에서 Snyk CLI를 통해 코드를 스캔하고, 위험도가 높은 취약점에 대해 AI 수정을 시도합니다.
   * 처리 후 기존에 생성된 "분석 중" Jira 티켓을 최종 결과로 업데이트합니다.
   *
   * @param issueKey 단계 1에서 생성된 Jira 티켓 Key
   * @param repoName 저장소 이름 (티켓 업데이트 시 사용)
   * @param scanPath 스캔할 로컬 디렉토리 경로 (null인 경우 전역 환경변수 LOCAL_REPO_PATH 사용)
   */
  @Async("securityTaskExecutor")
  public void runSnykScanAndUpdate(String issueKey, String repoName, String scanPath) {
    log.info("[Orchestrator][Async] Step2 시작 - issueKey={}, repo={}, aiEngine={}",
        issueKey, repoName, aiRemediationService.providerName());

    try {
      // A. Snyk REST API 스캔 - 이제 CLI 대신 API를 사용하여 클라우드에서도 작동합니다.
      log.info("[Orchestrator][Async] Snyk REST API를 통해 취약점 수집 중...");
      List<Map<String, Object>> rawIssues = snykClient.fetchVulnerabilities();
      List<UnifiedIssue> issues = rawIssues.stream()
          .map(snykParser::toUnifiedIssue)
          .toList();
      log.info("[Orchestrator][Async] API 스캔 완료 - 취약점 {}건", issues.size());

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
          "Snyk 보안 분석 중 오류: " + e.getMessage());
    }
  }

  @Async("securityTaskExecutor")
  public void runSnykScanAndUpdate(String issueKey, String repoName) {
    runSnykScanAndUpdate(issueKey, repoName, null);
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

    List<UnifiedIssue> targets = issues.stream()
        .filter(i -> i.getSeverity() == UnifiedIssue.SeverityLevel.CRITICAL
            || i.getSeverity() == UnifiedIssue.SeverityLevel.HIGH)
        .toList();

    java.util.Set<String> processedIds = new java.util.HashSet<>();

    log.info("[Orchestrator][AI] CRITICAL/HIGH {}건 AI 수정 시도 및 티켓 생성", targets.size());

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
    boolean isAiFixed = false;
    String fixedCode = "";
    String explanation = "";
    String originalCode = "";

    try {
      originalCode = readSourceFile(issue);
      String vulnInfo = buildVulnerabilityInfo(issue);
      AiRemediationResult result = aiRemediationService.fixCode(originalCode, vulnInfo);
      fixedCode = result.getFixedCode();
      explanation = result.getExplanation();

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
      Integer prNumber = githubService.createPullRequest(issue, originalCode, fixedCode, explanation);
      if (prNumber != null) {
        securityLog.setPrNumber(prNumber);
        securityLogRepository.save(securityLog);

        String prUrl = "https://github.com/" + githubService.getRepoName() + "/pull/" + prNumber;
        discordNotificationService.sendPrCreatedAlert(
            "fix/auto-fix-" + issue.getId().replaceAll("[^a-zA-Z0-9-]", "-"),
            prUrl,
            dashboardDetailUrl);
      }
    }
  }

  /**
   * 취약점 정보(description)에서 파일 경로를 추출해 로컬 디스크에서 원본 소스코드를 읽어옵니다.
   *
   * @param issue 취약점 DTO
   * @return 파일의 원본 내용, 또는 오류 발생 시 에러 메시지(주석 형태)
   */
  private String readSourceFile(UnifiedIssue issue) {
    String filePath = extractFilePath(issue.getDescription());
    if (filePath == null) {
      return "// 파일 경로 정보 없음\n" + issue.getDescription();
    }

    // 1. 먼저 GitHub API를 통해 원격 코드를 가져옵니다 (클라우드 환경 우선)
    String remoteCode = githubService.getFileContentAsString(filePath, null);
    if (remoteCode != null) {
      log.info("[Orchestrator][Remote] GitHub에서 파일 읽기 성공: {}", filePath);
      return remoteCode;
    }

    // 2. 실패 시 로컬 파일 시스템에서 시도합니다 (하이브리드 지원)
    if (localRepoPath != null && !localRepoPath.isBlank()) {
      try {
        return Files.readString(Path.of(localRepoPath, filePath));
      } catch (IOException e) {
        log.warn("[Orchestrator][Local] 로컬 파일 읽기 실패: {}", filePath);
      }
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
    sb.append(String.format("⚠️ Snyk 보안 분석 완료: %d건 발견\n", issues.size()));
    sb.append(String.format("🤖 AI(%s) 자동 수정: %d건\n", aiRemediationService.providerName(), aiFixedCount));
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

  /**
   * PR Merge 이벤트 수신 시 티켓 상태를 Done으로 전환합니다.
   */
  public boolean completeJiraTicket(String jiraKey) {
    log.info("[Orchestrator] PR Merge 감지 - Jira 티켓 완료 처리: {}", jiraKey);
    return jiraService.transitionIssue(jiraKey, jiraConfig.getTransition().getDone());
  }
}
