package com.example.autohealing.orchestrator;

import com.example.autohealing.ai.AiRemediationService;
import com.example.autohealing.client.SnykCliScannerService;
import com.example.autohealing.parser.dto.UnifiedIssue;
import com.example.autohealing.service.JiraService;
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
 * │ C. CRITICAL/HIGH 취약점별 AI 자동 수정 시도               │
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

  @Value("${LOCAL_REPO_PATH:}")
  private String localRepoPath;

  // ─────────────────────────────────────────────────────────────────────────
  // Step 1: 즉시 응답용 "분석 중" 티켓 생성 (동기)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * 웹훅 이벤트를 수신하고 즉시 "분석 중" Jira 티켓을 생성합니다.
   *
   * @return 생성된 Jira 이슈 키 (예: "SCRUM-42"). 실패 시 null.
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

  /**
   * 백그라운드에서 Snyk CLI 스캔 → AI 코드 수정 → Jira 티켓 업데이트를 실행합니다.
   *
   * @param issueKey Step1에서 생성된 Jira 이슈 키
   * @param repoName 저장소명
   * @param scanPath 스캔할 프로젝트 경로 (null이면 LOCAL_REPO_PATH 사용)
   */
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

      // B. CRITICAL/HIGH → AI 자동 수정
      int aiFixedCount = applyAiRemediation(issues);

      // C. Jira 최종 업데이트
      updateWithVulnerabilities(issueKey, repoName, issues, aiFixedCount);

    } catch (Exception e) {
      log.error("[Orchestrator][Async] 오류 발생 - issueKey={}", issueKey, e);
      jiraService.updateIssue(issueKey,
          "[보안 분석 실패] " + repoName,
          "Snyk CLI 스캔 중 오류: " + e.getMessage());
    }
  }

  /**
   * 하위 호환용 오버로드 - scanPath를 생략하면 LOCAL_REPO_PATH 사용.
   */
  @Async("securityTaskExecutor")
  public void runSnykScanAndUpdate(String issueKey, String repoName) {
    runSnykScanAndUpdate(issueKey, repoName, null);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – AI 수정
  // ─────────────────────────────────────────────────────────────────────────

  private int applyAiRemediation(List<UnifiedIssue> issues) {
    int fixedCount = 0;

    List<UnifiedIssue> targets = issues.stream()
        .filter(i -> i.getSeverity() == UnifiedIssue.SeverityLevel.CRITICAL
            || i.getSeverity() == UnifiedIssue.SeverityLevel.HIGH)
        .toList();

    log.info("[Orchestrator][AI] CRITICAL/HIGH {}건 AI 수정 시도", targets.size());

    for (UnifiedIssue issue : targets) {
      try {
        String originalCode = readSourceFile(issue);
        String vulnInfo = buildVulnerabilityInfo(issue);
        String fixedCode = aiRemediationService.fixCode(originalCode, vulnInfo);

        log.info("[Orchestrator][AI] 수정 완료 - id={} ({}자→{}자)",
            issue.getId(), originalCode.length(), fixedCode.length());

        // TODO: GithubService.createPR(fixedCode) 연동 예정
        fixedCount++;
      } catch (Exception e) {
        log.warn("[Orchestrator][AI] 수정 실패 - id={}", issue.getId(), e);
      }
    }
    return fixedCount;
  }

  private String readSourceFile(UnifiedIssue issue) {
    if (localRepoPath == null || localRepoPath.isBlank()) {
      return "// LOCAL_REPO_PATH 미설정\n" + issue.getDescription();
    }
    String filePath = extractFilePath(issue.getDescription());
    if (filePath == null)
      return "// 파일 경로 정보 없음\n" + issue.getDescription();
    try {
      return Files.readString(Path.of(localRepoPath, filePath));
    } catch (IOException e) {
      log.warn("[Orchestrator][AI] 파일 읽기 실패: {}", filePath);
      return "// 파일 읽기 실패: " + filePath;
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
      List<UnifiedIssue> issues, int aiFixedCount) {
    long critical = issues.stream()
        .filter(i -> i.getSeverity() == UnifiedIssue.SeverityLevel.CRITICAL).count();
    long high = issues.stream()
        .filter(i -> i.getSeverity() == UnifiedIssue.SeverityLevel.HIGH).count();

    String summary = String.format(
        "[보안 분석 완료] %s - 취약점 %d건 (C:%d/H:%d) | AI수정 %d건 ⚠️",
        repoName, issues.size(), critical, high, aiFixedCount);

    StringBuilder sb = new StringBuilder();
    sb.append(String.format("⚠️ Snyk CLI 스캔 완료: %d건 발견%n", issues.size()));
    sb.append(String.format("🤖 AI(%s) 자동 수정: %d건%n", aiRemediationService.providerName(), aiFixedCount));
    sb.append("──────────────────────────────\n");
    for (int i = 0; i < issues.size(); i++) {
      UnifiedIssue issue = issues.get(i);
      sb.append(String.format("[%d] [%s] %s%n    ID: %s%n%n",
          i + 1, issue.getSeverity(), issue.getTitle(), issue.getId()));
    }
    if (aiFixedCount > 0) {
      sb.append(String.format("🔧 %d건은 AI가 수정 코드를 생성했습니다.", aiFixedCount));
    }

    jiraService.updateIssue(issueKey, summary, sb.toString());

    // CRITICAL/HIGH 개별 Jira 티켓 생성
    issues.stream()
        .filter(i -> i.getSeverity() == UnifiedIssue.SeverityLevel.CRITICAL
            || i.getSeverity() == UnifiedIssue.SeverityLevel.HIGH)
        .forEach(issue -> {
          String key = jiraService.createIssue(issue.getTitle(), issue.getDescription());
          log.info("[Orchestrator][Async] 개별 티켓 생성: {} → {}", issue.getId(), key);
        });
  }
}
