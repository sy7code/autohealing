package com.example.autohealing.controller;

import com.example.autohealing.orchestrator.SecurityOrchestrator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.List;
import java.util.Map;

/**
 * GitHub Actions에서 Snyk CLI 스캔 결과를 수신하는 엔드포인트.
 *
 * <h3>흐름</h3>
 * <pre>
 * GitHub Actions (snyk test --json 결과)
 *   → POST /api/webhook/snyk
 *     { "repo": "org/repo", "commit": "abc1234", "committer": "user",
 *       "vulnerabilities": [...] }
 *   → SecurityOrchestrator.processSnykPayload() 호출
 *   → Jira 티켓 생성 + AI 수정
 * </pre>
 *
 * <h3>페이로드 구조</h3>
 * GitHub Actions에서 Snyk CLI 결과(snyk test --json)를 그대로 전달합니다.
 * 최상위에 repo, commit, committer 필드를 추가해 전송합니다.
 */
@Slf4j
@RestController
@RequestMapping("/api/webhook")
@RequiredArgsConstructor
// file deepcode ignore CSRF: Webhook endpoint, no session cookies used
public class SnykWebhookController {

  private final SecurityOrchestrator orchestrator;

  /**
   * GitHub Actions에서 Snyk 스캔 결과 수신.
   *
   * @param payload Snyk 스캔 결과 JSON
   *   - repo       : 저장소 이름 (예: my-org/my-repo)
   *   - commit     : 커밋 ID (8자리 이상)
   *   - committer  : 커밋 작성자
   *   - vulnerabilities : Snyk CLI 취약점 배열 (snyk test --json 의 vulnerabilities 필드)
   * @return 202 Accepted
   */
  @PostMapping("/snyk")
  public Mono<ResponseEntity<Map<String, String>>> handleSnykWebhook(
      @RequestBody Map<String, Object> payload) {

    String repo = extractString(payload, "repo", "unknown-repo");
    String commit = extractString(payload, "commit", "unknown-commit");
    String committer = extractString(payload, "committer", "unknown");
    int vulnCount = countVulnerabilities(payload);

    log.info("[SnykWebhook] GitHub Actions 스캔 결과 수신 - repo={}, commit={}, committer={}, vulns={}건",
        repo, commit, committer, vulnCount);

    return Mono.fromCallable(() -> orchestrator.startAnalysis(repo, commit, committer))
        .subscribeOn(Schedulers.boundedElastic())
        .map(issueKey -> {
          if (issueKey == null) {
            log.error("[SnykWebhook] Jira 초기 티켓 생성 실패 - repo={}", repo);
            return ResponseEntity.internalServerError()
                .<Map<String, String>>body(Map.of(
                    "status", "error",
                    "message", "Jira 티켓 생성 실패"));
          }
          log.info("[SnykWebhook] Jira 초기 티켓 생성 완료: {} → 비동기 처리 시작", issueKey);

          // 비동기: Snyk 결과 파싱 + AI 수정 + Jira 업데이트
          orchestrator.processSnykPayload(issueKey, repo, payload);

          return ResponseEntity.accepted()
              .<Map<String, String>>body(Map.of(
                  "status", "accepted",
                  "message", "Snyk 스캔 결과 처리를 시작합니다. Jira 티켓에 자동 업데이트됩니다.",
                  "issueKey", issueKey,
                  "repo", repo,
                  "commit", commit,
                  "vulnCount", String.valueOf(vulnCount)));
        })
        .onErrorResume(ex -> {
          log.error("[SnykWebhook] 처리 중 예외 발생 - repo={}", repo, ex);
          return Mono.just(ResponseEntity.internalServerError()
              .<Map<String, String>>body(Map.of(
                  "status", "error",
                  "message", "서버 내부 오류: " + ex.getMessage())));
        });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Private Helpers
  // ──────────────────────────────────────────────────────────────────────────

  private String extractString(Map<String, Object> map, String key, String defaultValue) {
    Object val = map.get(key);
    return (val instanceof String s && !s.isBlank()) ? s : defaultValue;
  }

  @SuppressWarnings("unchecked")
  private int countVulnerabilities(Map<String, Object> payload) {
    Object vulns = payload.get("vulnerabilities");
    if (vulns instanceof List<?> list) {
      return list.size();
    }
    return 0;
  }
}
