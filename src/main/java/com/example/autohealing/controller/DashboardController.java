package com.example.autohealing.controller;

import com.example.autohealing.entity.SecurityLog;
import com.example.autohealing.repository.SecurityLogRepository;
import com.example.autohealing.service.GithubService;
import com.example.autohealing.service.JiraService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 프론트엔드 대시보드 및 승인 API를 제공하는 컨트롤러.
 */
@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class DashboardController {

  private final SecurityLogRepository securityLogRepository;
  private final JiraService jiraService;
  private final GithubService githubService;

  // ─────────────────────────────────────────────────────────────────────────
  // Dashboard APIs
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * 전체 통계 반환
   */
  @GetMapping("/dashboard/stats")
  public ResponseEntity<Map<String, Object>> getStats() {
    long totalFound = securityLogRepository.count();
    long aiFixed = securityLogRepository.countByAiFixedTrue();
    long approved = securityLogRepository.countByApprovedTrue();
    long critical = securityLogRepository.countBySeverityIgnoreCase("CRITICAL");
    long high = securityLogRepository.countBySeverityIgnoreCase("HIGH");
    long medium = securityLogRepository.countBySeverityIgnoreCase("MEDIUM");
    long low = securityLogRepository.countBySeverityIgnoreCase("LOW");
    long pending = totalFound - approved;

    Map<String, Object> stats = Map.of(
        "totalFound", totalFound,
        "aiFixed", aiFixed,
        "approved", approved,
        "pending", pending,
        "critical", critical,
        "high", high,
        "medium", medium,
        "low", low);

    return ResponseEntity.ok(stats);
  }

  /**
   * 최근 스캔된 취약점 리스트 반환
   */
  @GetMapping("/dashboard/list")
  public ResponseEntity<List<SecurityLog>> getList() {
    List<SecurityLog> logs = securityLogRepository.findTop100ByOrderByDetectedAtDesc();
    return ResponseEntity.ok(logs);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Approval API
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * 취약점 수정안을 승인합니다.
   * 1) GitHub PR 머지
   * 2) Jira 티켓 → Done
   * 3) DB 승인 업데이트
   */
  @PostMapping("/vulnerabilities/approve/{id}")
  public ResponseEntity<Map<String, Object>> approveVulnerability(@PathVariable Long id) {
    log.info("[Approval] 승인 요청 - id={}", id);

    SecurityLog logEntry = securityLogRepository.findById(id).orElse(null);
    if (logEntry == null) {
      return ResponseEntity.notFound().build();
    }

    if (logEntry.isApproved()) {
      return ResponseEntity.badRequest().body(Map.of(
          "error", "이미 승인된 항목입니다.",
          "id", id));
    }

    boolean prMerged = false;
    boolean jiraDone = false;

    // 1. GitHub PR 검증 및 머지
    if (logEntry.getPrNumber() != null && logEntry.getPrNumber() > 0) {
      int prNumber = logEntry.getPrNumber().intValue();

      log.info("[Approval] PR #{} 빌드/테스트 상태 확인을 시작합니다...", prNumber);
      boolean ciSuccess = githubService.isPrTestsSuccessful(prNumber);
      log.info("[Approval] PR #{} CI 자동 검증 결과 - passed={}", prNumber, ciSuccess);

      if (!ciSuccess) {
        return ResponseEntity.badRequest().body(Map.of(
            "error", "아직 테스트가 완료되지 않았습니다",
            "id", id));
      }

      prMerged = githubService.mergePullRequest(prNumber);
      log.info("[Approval] PR 머지 결과 - prNumber={}, success={}", prNumber, prMerged);
    } else {
      log.info("[Approval] PR 번호가 없어 머지를 건너뜁니다. id={}", id);
    }

    // 2. Jira 티켓 → Done
    if (logEntry.getJiraKey() != null && !logEntry.getJiraKey().isBlank()) {
      jiraDone = jiraService.transitionIssue(logEntry.getJiraKey(), "Done");
      log.info("[Approval] Jira 전환 결과 - key={}, success={}", logEntry.getJiraKey(), jiraDone);
    } else {
      log.info("[Approval] Jira 키가 없어 전환을 건너뜁니다. id={}", id);
    }

    // 3. DB 승인 업데이트
    logEntry.setApproved(true);
    logEntry.setStatus("APPROVED");
    securityLogRepository.save(logEntry);

    log.info("[Approval] 승인 완료 - id={}", id);

    return ResponseEntity.ok(Map.of(
        "id", id,
        "approved", true,
        "prMerged", prMerged,
        "jiraDone", jiraDone));
  }
}
