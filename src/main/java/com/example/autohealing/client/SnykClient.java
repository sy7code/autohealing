package com.example.autohealing.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Snyk 클라이언트 (REST v3 + v1 혼합 전략).
 *
 * <pre>
 * Step1: GET  /rest/orgs/{orgId}/projects  → 프로젝트 ID 목록 (REST v3)
 * Step2: POST /v1/org/{orgId}/project/{projectId}/issues → 이슈 목록 (v1, 아직 유효)
 * </pre>
 *
 * <p>
 * SNYK_API_TOKEN, SNYK_ORG_ID는 {@code .env}에 설정하세요.
 */
@Slf4j
@Component
public class SnykClient {

  private static final String SNYK_REST_BASE = "https://api.snyk.io/rest";
  private static final String SNYK_V1_BASE = "https://api.snyk.io/v1";
  private static final String SNYK_API_VERSION = "2024-10-15";

  private final WebClient webClient;
  private final String snykApiToken;
  private final String snykOrgId;

  public SnykClient(WebClient webClient,
      @Value("${SNYK_API_TOKEN:}") String snykApiToken,
      @Value("${SNYK_ORG_ID:}") String snykOrgId) {
    this.webClient = webClient;
    this.snykApiToken = snykApiToken;
    this.snykOrgId = snykOrgId;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public API
  // ─────────────────────────────────────────────────────────────────────────

  @SuppressWarnings("unchecked")
  public List<Map<String, Object>> fetchVulnerabilities() {
    if (snykApiToken == null || snykApiToken.isBlank()) {
      log.warn("[SnykClient] SNYK_API_TOKEN 미설정 → Mock 데이터 반환");
      return mockVulnerabilities();
    }
    if (snykOrgId == null || snykOrgId.isBlank()) {
      log.error("[SnykClient] SNYK_ORG_ID 미설정 → .env에 추가하세요.");
      return Collections.emptyList();
    }

    try {
      // Step1: REST v3로 프로젝트 목록 조회
      List<String> projectIds = fetchProjectIds();
      if (projectIds.isEmpty()) {
        log.warn("[SnykClient] 프로젝트 없음 - orgId={}", snykOrgId);
        return mockVulnerabilities(); // 프로젝트 없으면 Mock으로 대체
      }
      log.info("[SnykClient] 프로젝트 {}개 발견", projectIds.size());

      // Step2: 각 프로젝트 이슈 수집 (v1 endpoint)
      return projectIds.stream()
          .flatMap(projectId -> fetchIssuesV1(projectId).stream())
          .toList();

    } catch (Exception e) {
      log.error("[SnykClient] 취약점 조회 오류", e);
      return Collections.emptyList();
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – Step1: REST v3 프로젝트 목록
  // ─────────────────────────────────────────────────────────────────────────

  @SuppressWarnings("unchecked")
  private List<String> fetchProjectIds() {
    try {
      Map<String, Object> response = webClient.get()
          .uri(SNYK_REST_BASE + "/orgs/{orgId}/projects?version={ver}&limit=100",
              snykOrgId, SNYK_API_VERSION)
          .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
          .header(HttpHeaders.ACCEPT, "application/vnd.api+json")
          .retrieve()
          .bodyToMono(Map.class)
          .block();

      if (response == null)
        return Collections.emptyList();

      List<Map<String, Object>> data = (List<Map<String, Object>>) response.get("data");
      if (data == null)
        return Collections.emptyList();

      return data.stream()
          .map(p -> (String) p.get("id"))
          .filter(id -> id != null)
          .toList();

    } catch (WebClientResponseException ex) {
      log.error("[SnykClient] 프로젝트 목록 조회 실패 - status={}, body={}",
          ex.getStatusCode(), ex.getResponseBodyAsString());
      return Collections.emptyList();
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – Step2: v1 프로젝트 이슈 조회
  // ─────────────────────────────────────────────────────────────────────────

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> fetchIssuesV1(String projectId) {
    try {
      log.info("[SnykClient] 이슈 조회 - projectId={}", projectId);

      Map<String, Object> response = webClient.post()
          .uri(SNYK_V1_BASE + "/org/{orgId}/project/{projectId}/issues",
              snykOrgId, projectId)
          .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
          .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
          .bodyValue(Map.of("filters", Map.of(
              "severities", List.of("critical", "high", "medium"),
              "types", List.of("vuln"))))
          .retrieve()
          .bodyToMono(Map.class)
          .block();

      if (response == null)
        return Collections.emptyList();

      Map<String, Object> issues = (Map<String, Object>) response.get("issues");
      if (issues == null)
        return Collections.emptyList();

      List<Map<String, Object>> vulns = (List<Map<String, Object>>) issues.get("vulnerabilities");
      List<Map<String, Object>> result = vulns != null ? vulns : Collections.emptyList();
      log.info("[SnykClient] projectId={} → {}건", projectId, result.size());
      return result;

    } catch (WebClientResponseException ex) {
      log.error("[SnykClient] 이슈 조회 실패 - projectId={}, status={}, body={}",
          projectId, ex.getStatusCode(), ex.getResponseBodyAsString());
      return Collections.emptyList();
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Mock
  // ─────────────────────────────────────────────────────────────────────────

  private List<Map<String, Object>> mockVulnerabilities() {
    log.info("[SnykClient] Mock 취약점 데이터 2건 반환");
    return List.of(
        Map.of(
            "id", "SNYK-JAVA-LOG4J-2314923",
            "title", "Remote Code Execution in Log4Shell",
            "description", "Log4j2 JNDI lookup allows remote attackers to execute arbitrary code.",
            "severity", "critical",
            "packageName", "log4j-core",
            "version", "2.14.1"),
        Map.of(
            "id", "SNYK-JAVA-JACKSON-1234567",
            "title", "Improper Input Validation in Jackson",
            "description", "Missing input validation allows type confusion attacks.",
            "severity", "high",
            "packageName", "jackson-databind",
            "version", "2.12.0"));
  }
}
