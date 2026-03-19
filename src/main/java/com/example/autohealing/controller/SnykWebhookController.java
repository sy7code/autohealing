package com.example.autohealing.controller;

import com.example.autohealing.orchestrator.SecurityOrchestrator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * GitHub Actions에서 Snyk CLI 스캔 결과를 수신하는 엔드포인트.
 *
 * <p>workflow에서 snyk-result.json을 그대로 POST하며,
 * repo/commit/committer는 HTTP 헤더로 전달합니다.
 * JSON 파싱은 서버(Java)에서 처리합니다.
 *
 * <p>Snyk CLI --json-file-output 결과 형식:
 * <ul>
 *   <li>단일 프로젝트: { "vulnerabilities": [...], ... }
 *   <li>--all-projects: [{ "vulnerabilities": [...] }, ...]
 * </ul>
 */
@Slf4j
@RestController
@RequestMapping("/api/webhook")
@RequiredArgsConstructor
public class SnykWebhookController {

  private final SecurityOrchestrator orchestrator;

  @PostMapping("/snyk")
  public Mono<ResponseEntity<Map<String, String>>> handleSnykWebhook(
      @RequestHeader(value = "X-Repo", defaultValue = "unknown-repo") String repo,
      @RequestHeader(value = "X-Commit", defaultValue = "unknown-commit") String commitFull,
      @RequestHeader(value = "X-Committer", defaultValue = "unknown") String committer,
      @RequestBody Object rawBody) {

    String commit = commitFull.length() > 8 ? commitFull.substring(0, 8) : commitFull;

    // 배열(--all-projects)과 객체(단일 프로젝트) 모두 Map으로 정규화
    Map<String, Object> payload = normalize(rawBody);
    int vulnCount = countVulnerabilities(payload);

    log.info("[SnykWebhook] 스캔 결과 수신 - repo={}, commit={}, committer={}, vulns={}건",
        repo, commit, committer, vulnCount);

    return Mono.fromCallable(() -> orchestrator.startAnalysis(repo, commit, committer))
        .subscribeOn(Schedulers.boundedElastic())
        .map(issueKey -> {
          if (issueKey == null) {
            log.error("[SnykWebhook] Jira 초기 티켓 생성 실패 - repo={}", repo);
            return ResponseEntity.internalServerError()
                .<Map<String, String>>body(Map.of("status", "error", "message", "Jira 티켓 생성 실패"));
          }
          log.info("[SnykWebhook] Jira 초기 티켓 생성 완료: {} → 비동기 처리 시작", issueKey);
          orchestrator.processSnykPayload(issueKey, repo, payload);

          return ResponseEntity.accepted()
              .<Map<String, String>>body(Map.of(
                  "status", "accepted",
                  "issueKey", issueKey,
                  "vulnCount", String.valueOf(vulnCount)));
        })
        .onErrorResume(ex -> {
          log.error("[SnykWebhook] 처리 중 예외 - repo={}", repo, ex);
          return Mono.just(ResponseEntity.internalServerError()
              .<Map<String, String>>body(Map.of("status", "error", "message", ex.getMessage())));
        });
  }

  /**
   * Snyk 결과를 Map으로 정규화합니다.
   * --all-projects 배열이면 모든 vulnerabilities를 합쳐 단일 Map으로 반환합니다.
   */
  @SuppressWarnings("unchecked")
  private Map<String, Object> normalize(Object body) {
    if (body instanceof Map<?, ?> map) {
      // 단일 프로젝트 결과
      return (Map<String, Object>) map;
    }
    if (body instanceof List<?> list) {
      // --all-projects: 배열 → vulnerabilities 합치기
      List<Map<String, Object>> allVulns = new ArrayList<>();
      for (Object item : list) {
        if (item instanceof Map<?, ?> projectMap) {
          Object vulns = ((Map<String, Object>) projectMap).get("vulnerabilities");
          if (vulns instanceof List<?> vList) {
            for (Object v : vList) {
              if (v instanceof Map<?, ?> vuln) {
                allVulns.add((Map<String, Object>) vuln);
              }
            }
          }
        }
      }
      log.info("[SnykWebhook] --all-projects 배열 형식 - 프로젝트 {}개에서 취약점 {}건 합산",
          list.size(), allVulns.size());
      Map<String, Object> merged = new HashMap<>();
      merged.put("vulnerabilities", allVulns);
      return merged;
    }
    log.warn("[SnykWebhook] 알 수 없는 페이로드 형식: {}", body == null ? "null" : body.getClass());
    return Map.of("vulnerabilities", List.of());
  }

  @SuppressWarnings("unchecked")
  private int countVulnerabilities(Map<String, Object> payload) {
    Object vulns = payload.get("vulnerabilities");
    return vulns instanceof List<?> list ? list.size() : 0;
  }
}
