package com.example.autohealing.controller;

import com.example.autohealing.entity.SecurityLog;
import com.example.autohealing.repository.SecurityLogRepository;
import com.example.autohealing.service.DiscordNotificationService;
import com.example.autohealing.service.GithubService;
import com.example.autohealing.service.JiraService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 관리자 대시보드 및 취약점 검토 화면을 위한 REST API 컨트롤러.
 * 프론트엔드(Next.js)에서 필요한 통계 데이터 및 개별 로그(SecurityLog) 내역을 제공하며,
 * AI가 제안한 소스코드 수정안에 대한 최종 반영(승인) 처리 엔드포인트를 담당합니다.
 */
import org.springframework.security.access.prepost.PreAuthorize;

@Slf4j
@RestController
@RequestMapping("/api")
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Dashboard API", description = "Endpoints for vulnerability dashboard views and approval operations. Requires JWT Auth.")
@RequiredArgsConstructor
public class DashboardController {

  private final SecurityLogRepository securityLogRepository;
  private final GithubService githubService;
  private final JiraService jiraService;
  private final DiscordNotificationService discordNotificationService;

  /**
   * [GET] /api/dashboard/list
   * 최근 감지된 취약점 로그를 최신순으로 반환합니다. (기본 100건 제한)
   * 주로 대시보드 요약 테이블(Recent Vulnerabilities) 등에 사용됩니다.
   *
   * @return SecurityLog 리스트 (상태코드 200)
   */
  @Operation(summary = "Get Recent Vulnerabilities", description = "Returns the top 100 most recently detected vulnerabilities.")
  @GetMapping("/dashboard/list")
  public ResponseEntity<List<SecurityLog>> getList() {
    List<SecurityLog> logs = securityLogRepository.findTop100ByOrderByDetectedAtDesc();
    return ResponseEntity.ok(logs);
  }

  /**
   * [GET] /api/vulnerabilities
   * 전체 취약점 로그 목록을 프론트엔드 형식에 맞춘 DTO(SecurityLogDTO) 리스트로 변환하여 반환합니다.
   * 프론트엔드 상세 페이지 라우팅 및 리스트 표출 시 활용됩니다.
   *
   * @return 변환된 SecurityLogDTO 리스트 (최신순 정렬, 상태코드 200)
   */
  @Operation(summary = "Get All Vulnerabilities (DTO)", description = "Returns all vulnerabilities mapped to the frontend SecurityLogDTO format.")
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
   * [GET] /api/vulnerabilities/{id}
   * 특정 ID를 가진 취약점 로그의 상세 정보(원본 및 수정된 코드, 상세 설명 등)를 반환합니다.
   *
   * @param id 조회할 취약점 로그(SecurityLog)의 PK 식별자
   * @return 취약점 로그 정보 (존재하지 않으면 404 반환)
   */
  @Operation(summary = "Get Vulnerability Details", description = "Returns detailed information for a specific vulnerability ID.")
  @GetMapping("/vulnerabilities/{id}")
  public ResponseEntity<?> getVulnerabilityDetail(@PathVariable Long id) {
    Optional<SecurityLog> logOpt = securityLogRepository.findById(id);
    if (logOpt.isEmpty()) {
      return ResponseEntity.notFound().build();
    }
    return ResponseEntity.ok(SecurityLogDTO.fromEntity(logOpt.get()));
  }

  /**
   * [GET] /api/dashboard/stats
   * 대시보드 상단 요약 카드 및 심각도별 통계 차트를 그리기 위한 데이터를 집계하여 반환합니다.
   * 통계 내용: 총 발견 건수, AI 수정 건수, 승인된 건수, 심각도(CRITICAL, HIGH, MEDIUM, LOW)별 개수
   *
   * @return 통계 지표가 담긴 Map 객체 (상태코드 200)
   */
  @Operation(summary = "Get Dashboard Statistics", description = "Returns aggravated statistics (count by severity, AI fixed, etc.) for the dashboard overview.")
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
   * [POST] /api/vulnerabilities/approve/{id}
   * 관리자가 AI 자동 수정안을 검토 후 승인(Approve)할 때 호출되는 엔드포인트입니다.
   *
   * 주요 처리 로직:
   * 1. GitHub CI 검증 성공을 확인한 뒤 연동된 PR을 머지(Squash)
   * 2. 연동된 Jira 티켓 상태를 'Done'으로 변경
   * 3. DB 보안 로그 업데이트 (isApproved = true, status = APPROVED)
   *
   * @param id 승인할 취약점 로그의 PK 식별자
   * @return 승인 결과 메시지 및 상태 정보 Map 반환 (실패 시 400 에러)
   */
  @Operation(summary = "Approve Vulnerability Patch", description = "Approves an AI-generated fix, verifies CI status, merges the PR, and resolves the Jira ticket.")
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
      String targetRepo = logEntry.getRepoName(); // SecurityLog에 저장된 repoName 활용

      log.info("[Approval] PR #{} 빌드/테스트 상태 확인을 시작합니다... (repo: {})", prNumber, targetRepo);
      boolean ciSuccess = githubService.isPrTestsSuccessful(targetRepo, prNumber);
      log.info("[Approval] PR #{} CI 자동 검증 결과 - passed={}", prNumber, ciSuccess);

      if (!ciSuccess) {
        return ResponseEntity.badRequest().body("CI 테스트가 아직 진행 중이거나 실패했습니다. 잠시 후 다시 시도해주세요.");
      }

      prMerged = githubService.mergePullRequest(targetRepo, prNumber);
      log.info("[Approval] PR 머지 결과 - prNumber={}, success={}", prNumber, prMerged);

      if (prMerged) {
        String repoToUse = targetRepo != null && !targetRepo.isBlank() ? targetRepo : githubService.getDefaultRepoName();
        String prUrl = "https://github.com/" + repoToUse + "/pull/" + prNumber;
        discordNotificationService.sendMergeSuccessAlert(logEntry.getThreatType(), prUrl);
      }
    } else {
      log.info("[Approval] PR 번호가 없어 머지를 건너뜠니다. id={}", id);
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
