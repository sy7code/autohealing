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
   * 대시보드 통계 정보를 반환합니다.
   */
  @GetMapping("/dashboard/stats")
  public ResponseEntity<Map<String, Object>> getDashboardStats() {
    long totalFound = securityLogRepository.count();
    long approved = securityLogRepository.countByIsApprovedTrue();
    long pending = totalFound - approved;

    long highSeverityCount = securityLogRepository.countBySeverityIgnoreCase("HIGH")
        + securityLogRepository.countBySeverityIgnoreCase("CRITICAL");

    Map<String, Object> stats = Map.of(
        "totalFound", totalFound,
        "aiFixed", totalFound, // 현재 AI가 모두 패치를 제안했다고 가정
        "pending", pending,
        "approvedAndMerged", approved,
        "highSeverity", highSeverityCount);

    return ResponseEntity.ok(stats);
  }

  /**
   * 사용자가 UI에서 "Approve & Patch" 버튼을 클릭했을 때 호출되는 API.
   * PR CI 테스트 상태를 검증하고, 성공 시 머지/Jira 상태 변경을 수행합니다.
   */
  @PostMapping("/vulnerabilities/approve/{id}")
  public ResponseEntity<?> approveVulnerability(@PathVariable Long id) {
    log.info("[Dashboard] 승인 요청 수신: ID={}", id);

    SecurityLog logEntry = securityLogRepository.findById(id)
        .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 취약점 ID입니다."));

    if (logEntry.isApproved()) {
      return ResponseEntity.badRequest().body("이미 승인 및 처리된 취약점입니다.");
    }

    Integer prNumber = logEntry.getPrNumber();
    if (prNumber == null || prNumber <= 0) {
      return ResponseEntity.badRequest().body("연결된 GitHub Pull Request 번호가 없습니다.");
    }

    // 1. GitHub PR CI 테스트 진행/성공 상태 체크
    boolean isCiPassed = githubService.isPrTestsSuccessful(prNumber);
    if (!isCiPassed) {
      log.warn("[Dashboard] PR #{} CI 테스트가 아직 통과되지 않음.", prNumber);
      return ResponseEntity.badRequest().body("CI 테스트가 아직 진행 중이거나 실패했습니다. 잠시 후 다시 시도해주세요.");
    }

    // 2. PR 머지 수행
    boolean isMerged = githubService.mergePullRequest(prNumber);
    if (!isMerged) {
      return ResponseEntity.internalServerError().body("GitHub PR 머지에 실패했습니다.");
    }

    // 3. Jira 티켓 'Done' (또는 승인 완료 상태) 로 변경
    if (logEntry.getJiraKey() != null && !logEntry.getJiraKey().isBlank()) {
      try {
        // JiraService 내에 티켓을 Done 상태로 바꾸는 메서드가 있다고 가정(구현 필요)
        jiraService.transitionIssueToDone(logEntry.getJiraKey());
        log.info("[Dashboard] Jira 이슈 {} 완료 상태로 변경 성공", logEntry.getJiraKey());
      } catch (Exception e) {
        log.error("[Dashboard] Jira 상태 변경 실패 (이슈: {})", logEntry.getJiraKey(), e);
        // Jira 변경 실패가 전체 로직을 롤백시키지는 않도록 경고만 남김
      }
    }

    // 4. DB 상태 업데이트
    logEntry.setApproved(true);
    logEntry.setResolvedAt(LocalDateTime.now());
    securityLogRepository.save(logEntry);

    log.info("[Dashboard] 승인 및 자동 패치 적용 완료! ID={}", id);
    return ResponseEntity.ok(Map.of(
        "message", "성공적으로 승인되어 머지되었습니다.",
        "jiraKey", logEntry.getJiraKey() != null ? logEntry.getJiraKey() : ""));
  }
}
