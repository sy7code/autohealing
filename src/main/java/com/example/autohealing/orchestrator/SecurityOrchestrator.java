package com.example.autohealing.orchestrator;

import com.example.autohealing.ai.AiRemediationService;
import com.example.autohealing.ai.AiRemediationResult;
import com.example.autohealing.client.SnykCliScannerService;
import com.example.autohealing.entity.SecurityLog;
import com.example.autohealing.repository.SecurityLogRepository;
import com.example.autohealing.parser.dto.UnifiedIssue;
import com.example.autohealing.service.JiraService;
import com.example.autohealing.service.CodeValidatorService;
import com.example.autohealing.service.GithubService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

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
  private final SnykCliScannerService snykCliScannerService;
  private final AiRemediationService aiRemediationService;
  private final GithubService githubService;
  private final CodeValidatorService codeValidatorService;
  private final SecurityLogRepository securityLogRepository;

  @Value("${LOCAL_REPO_PATH:}")
  private String localRepoPath;

  @Value("${VERCEL_URL:http://localhost:3000}")
  private String vercelUrl;

  // ─────────────────────────────────────────────────────────────────────────
  // Step 1: 즉시 응답용 "분석 중" 티켓 생성 (동기)
  // ─────────────────────────────────────────────────────────────────────────

  public String startAnalysis(String repoName, String commitId, String committer) {
    log.info("[Orchestrator] 보안 분석 시작 - repo={}, commit={}", repoName, commitId);

    String summary = String.format("[보안 분석 중] %s - 커밋 %s", repoName, commitId);
    String description = String.format("""
        🔍 GitHub 커밋 감지 - 보안 스캔을 시작합니다.
        ──────────────────────────────
        저장소  : %s
        커밋 ID : %s
        작성자  : %s
        스캐너  : Snyk CLI
        AI 엔진 : %s
        ──────────────────────────────
        ⏳ Snyk CLI 스캔이 백그라운드에서 실행 중입니다.
        스캔 완료 후 이 티켓이 자동으로 업데이트됩니다.
        """, repoName, commitId, committer, aiRemediationService.providerName());

    return jiraService.createIssue(summary, description);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Step 2: 비동기 Snyk CLI 스캔 + AI 수정 + Jira 업데이트
  // ─────────────────────────────────────────────────────────────────────────

  @Async("securityTaskExecutor")
  public void runSnykScanAndUpdate(String issueKey, String repoName, String scanPath) {
    log.info("[Orchestrator][Async] Step2 시작 - issueKey={}, repo={}, aiEngine={}",
        issueKey, repoName, aiRemediationService.providerName());

    try {
      // A. Snyk CLI 스캔
      String targetPath = (scanPath != null && !scanPath.isBlank()) ? scanPath : localRepoPath;
      List<UnifiedIssue> issues = snykCliScannerService.scan(targetPath);
      log.info("[Orchestrator][Async] CLI 스캔 완료 - 취약점 {}건", issues.size());

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
          "Snyk CLI 스캔 중 오류: " + e.getMessage());
    }
  }

  @Async("securityTaskExecutor")
  public void runSnykScanAndUpdate(String issueKey, String repoName) {
    runSnykScanAndUpdate(issueKey, repoName, null);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – AI 수정 + 컴파일 검증
  // ─────────────────────────────────────────────────────────────────────────

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

        // 컴파일 유효성 검증
        String fileName = extractFilePath(issue.getDescription());
        if (fileName == null)
          fileName = "Unknown.java";

        String compileError = codeValidatorService.validateCode(fixedCode, fileName);

        if (compileError != null) {
          log.warn("[Orchestrator][AI] 컴파일 검증 실패 - id={}, error=\n{}", issue.getId(), compileError);
          jiraService.addCommentToIssue(issueKey,
              "🚨 **AI 수정안 컴파일 오류 발생**\n" +
                  "AI가 생성한 수정 코드가 컴파일되지 않아 PR 생성을 중단했습니다.\n" +
                  "**파일:** `" + fileName + "`\n" +
                  "**에러 내용:**\n{code:java}\n" + compileError + "\n{code}");
          // 컴파일 실패 → isAiFixed = false 유지
        } else {
          fixedIds.add(issue.getId());
          isAiFixed = true;
        }
      } catch (Exception e) {
        log.warn("[Orchestrator][AI] 수정 실패 - id={}", issue.getId(), e);
        explanation = "AI 자동 수정 중 오류 발생: " + e.getMessage();
      }

      // 0. DB에 SecurityLog 먼저 저장하여 ID 발급받기
      SecurityLog securityLog = new SecurityLog(
          repoName,
          issue.getTitle(),
          issue.getSeverity().name(),
          isAiFixed ? "AI 패치 대기중" : "수동 리뷰 필요");
      securityLog.setOriginalCode(originalCode);
      securityLog.setPatchedCode(fixedCode);
      securityLog.setFixExplanation(explanation);
      securityLog = securityLogRepository.save(securityLog);

      String dashboardDetailUrl = vercelUrl + "/detail/" + securityLog.getId();

      // 1. 개별 Jira 티켓 생성
      java.util.List<String> labels = new java.util.ArrayList<>();
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

      // Jira Key 업데이트
      if (jiraKey != null) {
        securityLog.setJiraKey(jiraKey);
        securityLogRepository.save(securityLog);
      }

      // 2. AI 수정 성공 + 컴파일 통과 시 PR에 Jira Key 넘겨주기 및 In Progress 전환
      if (isAiFixed && jiraKey != null) {
        jiraService.transitionIssue(jiraKey, "In Progress");
        Integer prNumber = githubService.createPullRequest(issue, originalCode, fixedCode,
            explanation + "\n\n**🔗 연동된 Jira 티켓:** " + jiraKey);
        if (prNumber != null) {
          securityLog.setPrNumber(prNumber);
          securityLogRepository.save(securityLog);
        }
      } else if (isAiFixed) {
        Integer prNumber = githubService.createPullRequest(issue, originalCode, fixedCode, explanation);
        if (prNumber != null) {
          securityLog.setPrNumber(prNumber);
          securityLogRepository.save(securityLog);
        }
      }
    }
    return fixedIds;
  }

  private String readSourceFile(UnifiedIssue issue) {
    if (localRepoPath == null || localRepoPath.isBlank()) {
      return "// LOCAL_REPO_PATH 미설정\n" + issue.getDescription();
    }
    String filePath = extractFilePath(issue.getDescription());
    if (filePath == null) {
      return "// 파일 경로 정보 없음\n" + issue.getDescription();
    }
    try {
      return Files.readString(Path.of(localRepoPath, filePath));
    } catch (java.nio.file.InvalidPathException e) {
      log.warn("[Orchestrator][AI] 잘못된 파일 경로 형식: {}", filePath);
      return "// 잘못된 파일 경로 형식: " + filePath + "\n" + issue.getDescription();
    } catch (IOException e) {
      log.warn("[Orchestrator][AI] 파일 읽기 실패: {}", filePath);
      return "// 파일 읽기 실패: " + filePath + "\n" + issue.getDescription();
    }
  }

  private String buildVulnerabilityInfo(UnifiedIssue issue) {
    return String.format("ID: %s | 심각도: %s | 제목: %s\n%s",
        issue.getId(), issue.getSeverity(), issue.getTitle(), issue.getDescription());
  }

  private String extractFilePath(String description) {
    if (description == null)
      return null;
    for (String line : description.lines().toList()) {
      if (line.toLowerCase().startsWith("패키지 경로") || line.toLowerCase().startsWith("file")) {
        String[] parts = line.split(":", 2);
        if (parts.length == 2)
          return parts[1].trim();
      }
    }
    return null;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – Jira 업데이트
  // ─────────────────────────────────────────────────────────────────────────

  private void updateWithNoIssues(String issueKey, String repoName) {
    log.info("[Orchestrator][Async] 취약점 없음 - 티켓 업데이트: {}", issueKey);
    jiraService.updateIssue(
        issueKey,
        "[보안 분석 완료] " + repoName + " - 취약점 없음 ✅",
        "✅ Snyk CLI 스캔 완료: 감지된 취약점이 없습니다.");
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
    sb.append(String.format("⚠️ Snyk CLI 스캔 완료: %d건 발견\n", issues.size()));
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
    return jiraService.transitionIssue(jiraKey, "Done");
  }
}
