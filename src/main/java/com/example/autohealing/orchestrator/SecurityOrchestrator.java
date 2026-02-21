package com.example.autohealing.orchestrator;

import com.example.autohealing.client.SnykClient;
import com.example.autohealing.parser.IssueManager;
import com.example.autohealing.parser.dto.UnifiedIssue;
import com.example.autohealing.service.JiraService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * GitHub Webhook 수신 후 2단계 보안 분석을 오케스트레이션하는 서비스.
 *
 * <h3>실행 흐름</h3>
 * 
 * <pre>
 * [Step 1 - 동기] 웹훅 수신 즉시 "분석 중" Jira 티켓 생성 → issueKey 반환
 *       ↓
 * [Step 2 - 비동기 @Async] Snyk 스캔 실행
 *       ↓
 * 스캔 결과로 Step1 티켓 내용 업데이트 (updateIssue)
 * </pre>
 *
 * <p>
 * 웹훅 컨트롤러는 Step 1 후 즉시 202 Accepted를 반환하고,
 * Step 2는 "security-scan-*" 스레드 풀에서 백그라운드로 실행됩니다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityOrchestrator {

  private final JiraService jiraService;
  private final SnykClient snykClient;
  private final IssueManager issueManager;

  // ─────────────────────────────────────────────────────────────────────────
  // Step 1: 즉시 응답용 "분석 중" 티켓 생성 (동기)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * 웹훅 이벤트를 수신하고 즉시 "분석 중" Jira 티켓을 생성합니다.
   *
   * @param repoName  커밋이 발생한 저장소 이름
   * @param commitId  커밋 SHA
   * @param committer 커밋 작성자
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
        ──────────────────────────────
        ⏳ Snyk 스캔이 백그라운드에서 실행 중입니다.
        스캔 완료 후 이 티켓이 자동으로 업데이트됩니다.
        """, repoName, commitId, committer);

    return jiraService.createIssue(summary, description);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Step 2: 비동기 Snyk 스캔 + Jira 티켓 업데이트
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * 백그라운드에서 Snyk 스캔을 실행하고 결과로 Jira 티켓을 업데이트합니다.
   *
   * <p>
   * {@code @Async("securityTaskExecutor")} 로 지정된 스레드 풀에서 실행되므로
   * 호출 즉시 반환되며 완료를 기다리지 않습니다.
   *
   * @param issueKey Jira 이슈 키 (Step 1에서 생성된 키)
   * @param repoName 스캔 대상 저장소 이름
   */
  @Async("securityTaskExecutor")
  public void runSnykScanAndUpdate(String issueKey, String repoName) {
    log.info("[Orchestrator][Async] Snyk 스캔 시작 - issueKey={}, repo={}", issueKey, repoName);

    try {
      // ── 2-1. Snyk API 호출 (Token 없으면 Mock 데이터 반환) ─────────
      List<Map<String, Object>> rawVulns = snykClient.fetchVulnerabilities();
      log.info("[Orchestrator][Async] Snyk 스캔 완료 - 원시 취약점 수: {}", rawVulns.size());

      // ── 2-2. UnifiedIssue 로 파싱 ─────────────────────────────────
      Map<String, Object> snykData = Map.of("vulnerabilities", rawVulns);
      List<UnifiedIssue> issues = issueManager.parse("SNYK", snykData);

      // ── 2-3. 결과로 Jira 티켓 업데이트 ──────────────────────────
      if (issues.isEmpty()) {
        updateWithNoIssues(issueKey, repoName);
      } else {
        updateWithVulnerabilities(issueKey, repoName, issues);
      }

    } catch (Exception e) {
      log.error("[Orchestrator][Async] Snyk 스캔 중 오류 발생 - issueKey={}", issueKey, e);
      jiraService.updateIssue(
          issueKey,
          "[보안 분석 실패] " + repoName,
          "Snyk 스캔 중 오류가 발생했습니다. 시스템 로그를 확인하세요.\n오류: " + e.getMessage());
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private Helpers
  // ─────────────────────────────────────────────────────────────────────────

  private void updateWithNoIssues(String issueKey, String repoName) {
    log.info("[Orchestrator][Async] 취약점 없음 - 티켓 업데이트: {}", issueKey);
    jiraService.updateIssue(
        issueKey,
        "[보안 분석 완료] " + repoName + " - 취약점 없음 ✅",
        "✅ Snyk 스캔 완료: 감지된 취약점이 없습니다.");
  }

  private void updateWithVulnerabilities(String issueKey, String repoName,
      List<UnifiedIssue> issues) {
    log.info("[Orchestrator][Async] 취약점 {}건 감지 - 티켓 업데이트: {}", issues.size(), issueKey);

    // 심각도 통계 계산
    long criticalCount = issues.stream()
        .filter(i -> i.getSeverity() == UnifiedIssue.SeverityLevel.CRITICAL).count();
    long highCount = issues.stream()
        .filter(i -> i.getSeverity() == UnifiedIssue.SeverityLevel.HIGH).count();

    String summary = String.format("[보안 분석 완료] %s - 취약점 %d건 (Critical:%d / High:%d) ⚠️",
        repoName, issues.size(), criticalCount, highCount);

    StringBuilder sb = new StringBuilder();
    sb.append(String.format("⚠️ Snyk 스캔 완료: %d건의 취약점이 발견되었습니다.%n", issues.size()));
    sb.append("──────────────────────────────\n");

    for (int i = 0; i < issues.size(); i++) {
      UnifiedIssue issue = issues.get(i);
      sb.append(String.format("[%d] [%s] %s%n    ID: %s%n%n",
          i + 1, issue.getSeverity(), issue.getTitle(), issue.getId()));
    }
    sb.append("──────────────────────────────\n");
    sb.append("각 취약점에 대한 상세 Jira 티켓이 별도 생성되었습니다.");

    jiraService.updateIssue(issueKey, summary, sb.toString());

    // 심각한 이슈는 개별 Jira 티켓도 추가 생성
    issues.stream()
        .filter(i -> i.getSeverity() == UnifiedIssue.SeverityLevel.CRITICAL
            || i.getSeverity() == UnifiedIssue.SeverityLevel.HIGH)
        .forEach(issue -> {
          String key = jiraService.createIssue(issue.getTitle(), issue.getDescription());
          log.info("[Orchestrator][Async] 개별 티켓 생성: {} → {}", issue.getId(), key);
        });
  }
}
