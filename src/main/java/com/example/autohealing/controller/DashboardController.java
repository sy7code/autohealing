package com.example.autohealing.controller;

import com.example.autohealing.entity.SecurityLog;
import com.example.autohealing.repository.SecurityLogRepository;
import com.example.autohealing.service.GithubService;
import com.example.autohealing.service.JiraService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class DashboardController {

  private final SecurityLogRepository securityLogRepository;
  private final GithubService githubService;
  private final JiraService jiraService;

  /**
   * 전체 관리자 대시보드 리스트 반환 (최신순 100건 등)
   */
  @GetMapping("/dashboard/list")
  public ResponseEntity<List<SecurityLog>> getList() {
    List<SecurityLog> logs = securityLogRepository.findTop100ByOrderByDetectedAtDesc();
    return ResponseEntity.ok(logs);
  }

  /**
   * 전체 취약점 로그 목록을 반환합니다. (최신순)
   */
  @GetMapping("/vulnerabilities")
  public ResponseEntity<List<SecurityLogDTO>> getAllVulnerabilities() {
    // 실제 운영 시 페이징 처리 권장 (Pageable)
    List<SecurityLog> logs = securityLogRepository.findAll();
    // ID 기준 내림차순(최신순)으로 정렬하여 반환
    List<SecurityLogDTO> dtoList = logs.stream()
        .sorted((a, b) -> b.getId().compareTo(a.getId()))
        .map(SecurityLogDTO::fromEntity)
        .toList();
    return ResponseEntity.ok(dtoList);
  }

  /**
   * 프론트엔드 요구사항에 맞춘 DTO
   */
  @lombok.Data
  @lombok.Builder
  public static class SecurityLogDTO {
    private Long id;
    private String resourceName;
    private String threatType;
    private String severity;
    private String status;
    private LocalDateTime detectedAt;
    private String jiraKey;
    private Integer prNumber;
    private boolean isApproved;
    private LocalDateTime resolvedAt;
    private String originalCode;

    // 프론트엔드 기대 필드명으로 매핑
    private String fixedCode;
    private String aiExplanation;
    private String approvalStatus;

    public static SecurityLogDTO fromEntity(SecurityLog log) {
      return SecurityLogDTO.builder()
          .id(log.getId())
          .resourceName(log.getResourceName())
          .threatType(log.getThreatType())
          .severity(log.getSeverity())
          .status(log.getStatus())
          .detectedAt(log.getDetectedAt())
          .jiraKey(log.getJiraKey())
          .prNumber(log.getPrNumber())
          .isApproved(log.isApproved())
          .resolvedAt(log.getResolvedAt())
          .originalCode(log.getOriginalCode() != null ? log.getOriginalCode()
              : "public void process(String input) {\n  System.out.println(input);\n  // VULNERABLE CODE\n}")
          .fixedCode(log.getPatchedCode() != null ? log.getPatchedCode()
              : "public void process(String input) {\n  if (input == null) return;\n  // SECURE CODE\n  System.out.println(sanitize(input));\n}")
          .aiExplanation(log.getFixExplanation() != null ? log.getFixExplanation()
              : "Added null check and input sanitization to prevent potential injection.")
          .approvalStatus(log.isApproved() ? "APPROVED" : "PENDING") // boolean을 문자열로
          .build();
    }
  }

  /**
   * 특정 취약점 로그 상세를 반환합니다.
   */
  @GetMapping("/vulnerabilities/{id}")
  public ResponseEntity<?> getVulnerabilityDetail(@PathVariable Long id) {
    Optional<SecurityLog> logOpt = securityLogRepository.findById(id);
    if (logOpt.isEmpty()) {
      return ResponseEntity.notFound().build();
    }
    return ResponseEntity.ok(SecurityLogDTO.fromEntity(logOpt.get()));
  }

  /**
   * 대시보드 통계 반환
   */
  @GetMapping("/dashboard/stats")
  public ResponseEntity<Map<String, Object>> getStats() {
    long totalFound = securityLogRepository.count();
    long aiFixed = securityLogRepository.countByAiFixedTrue();
    long approved = securityLogRepository.countByIsApprovedTrue();
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
   * 취약점 수정안을 승인합니다.
   * 1) GitHub PR 머지
   * 2) Jira 티켓 → Done
   * 3) DB 승인 업데이트
   */
  @PostMapping("/vulnerabilities/approve/{id}")
  public ResponseEntity<?> approveVulnerability(@PathVariable Long id) {
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
        return ResponseEntity.badRequest().body("CI 테스트가 아직 진행 중이거나 실패했습니다. 잠시 후 다시 시도해주세요.");
      }

      prMerged = githubService.mergePullRequest(prNumber);
      log.info("[Approval] PR 머지 결과 - prNumber={}, success={}", prNumber, prMerged);
    } else {
      log.info("[Approval] PR 번호가 없어 머지를 건너뜁니다. id={}", id);
    }

    // 2. Jira 티켓 → Done
    if (logEntry.getJiraKey() != null && !logEntry.getJiraKey().isBlank()) {
      try {
        jiraDone = jiraService.transitionIssueToDone(logEntry.getJiraKey());
        log.info("[Approval] Jira 전환 결과 - key={}, success={}", logEntry.getJiraKey(), jiraDone);
      } catch (Exception e) {
        log.error("[Dashboard] Jira 상태 변경 실패 (이슈: {})", logEntry.getJiraKey(), e);
      }
    } else {
      log.info("[Approval] Jira 키가 없어 전환을 건너뜁니다. id={}", id);
    }

    // 3. DB 승인 업데이트
    logEntry.setApproved(true);
    logEntry.setStatus("APPROVED");
    logEntry.setResolvedAt(LocalDateTime.now());
    securityLogRepository.save(logEntry);

    log.info("[Approval] 승인 완료 - id={}", id);

    return ResponseEntity.ok(Map.of(
        "message", "성공적으로 승인되어 머지되었습니다.",
        "jiraKey", logEntry.getJiraKey() != null ? logEntry.getJiraKey() : "",
        "id", id,
        "approved", true,
        "prMerged", prMerged,
        "jiraDone", jiraDone));
  }
}
