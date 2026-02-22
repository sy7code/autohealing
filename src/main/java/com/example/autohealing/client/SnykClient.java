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
 * Snyk REST API v1 클라이언트.
 *
 * <h3>인증</h3>
 * {@code Authorization: token <SNYK_API_TOKEN>} 헤더를 사용합니다.
 *
 * <h3>주요 흐름</h3>
 * <ol>
 * <li>조직 목록 조회 ({@code /orgs})</li>
 * <li>첫 번째 조직의 프로젝트 목록 조회</li>
 * <li>각 프로젝트의 취약점 이슈 조회</li>
 * </ol>
 *
 * <p>
 * SNYK_API_TOKEN 은 {@code .env} 파일에 설정하세요.
 */
@Slf4j
@Component
public class SnykClient {

  private static final String SNYK_API_BASE = "https://snyk.io/api/v1";

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

  /**
   * 첫 번째 Snyk 조직의 모든 프로젝트에서 취약점 이슈를 수집합니다.
   *
   * @return 취약점 이슈 Map 목록 (각 Map은 개별 취약점 데이터)
   */
  public List<Map<String, Object>> fetchVulnerabilities() {
    if (snykApiToken == null || snykApiToken.isBlank()) {
      log.warn("[SnykClient] SNYK_API_TOKEN이 설정되지 않았습니다. Mock 데이터를 반환합니다.");
      return mockVulnerabilities();
    }

    try {
      // 1단계: Org ID 결정 (환경변수 우선, 없으면 API로 조회)
      String orgId;
      if (snykOrgId != null && !snykOrgId.isBlank()) {
        orgId = snykOrgId;
        log.info("[SnykClient] SNYK_ORG_ID 환경변수 사용: {}", orgId);
      } else {
        orgId = fetchFirstOrgId();
        if (orgId == null) {
          log.error("[SnykClient] 조직 정보를 가져올 수 없습니다. SNYK_ORG_ID를 .env에 설정하면 이 호출을 생략할 수 있습니다.");
          return Collections.emptyList();
        }
        log.info("[SnykClient] /orgs API로 조회한 조직 ID: {}", orgId);
      }

      // 2단계: 프로젝트 목록 조회
      List<Map<String, Object>> projects = fetchProjects(orgId);
      if (projects.isEmpty()) {
        log.warn("[SnykClient] 조직에 프로젝트가 없습니다. orgId={}", orgId);
        return Collections.emptyList();
      }
      log.info("[SnykClient] 발견된 프로젝트 수: {}", projects.size());

      // 3단계: 각 프로젝트의 취약점 수집
      return projects.stream()
          .flatMap(project -> {
            String projectId = (String) project.get("id");
            String projectName = (String) project.get("name");
            log.info("[SnykClient] 프로젝트 스캔 중: {} ({})", projectName, projectId);
            return fetchIssues(orgId, projectId).stream();
          })
          .toList();

    } catch (Exception e) {
      log.error("[SnykClient] 취약점 조회 중 오류 발생", e);
      return Collections.emptyList();
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – Snyk API Calls
  // ─────────────────────────────────────────────────────────────────────────

  @SuppressWarnings("unchecked")
  private String fetchFirstOrgId() {
    try {
      Map<String, Object> response = webClient.get()
          .uri(SNYK_API_BASE + "/orgs")
          .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
          .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
          .retrieve()
          .bodyToMono(Map.class)
          .block();

      if (response == null)
        return null;
      List<Map<String, Object>> orgs = (List<Map<String, Object>>) response.get("orgs");
      if (orgs == null || orgs.isEmpty())
        return null;
      return (String) orgs.get(0).get("id");

    } catch (WebClientResponseException ex) {
      log.error("[SnykClient] 조직 조회 실패 - status={}, body={}",
          ex.getStatusCode(), ex.getResponseBodyAsString());
      return null;
    }
  }

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> fetchProjects(String orgId) {
    try {
      Map<String, Object> response = webClient.get()
          .uri(SNYK_API_BASE + "/org/{orgId}/projects", orgId)
          .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
          .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
          .retrieve()
          .bodyToMono(Map.class)
          .block();

      if (response == null)
        return Collections.emptyList();
      List<Map<String, Object>> projects = (List<Map<String, Object>>) response.get("projects");
      return projects != null ? projects : Collections.emptyList();

    } catch (WebClientResponseException ex) {
      log.error("[SnykClient] 프로젝트 조회 실패 - orgId={}, status={}", orgId, ex.getStatusCode());
      return Collections.emptyList();
    }
  }

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> fetchIssues(String orgId, String projectId) {
    try {
      Map<String, Object> response = webClient.post()
          .uri(SNYK_API_BASE + "/org/{orgId}/project/{projectId}/issues", orgId, projectId)
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
      return vulns != null ? vulns : Collections.emptyList();

    } catch (WebClientResponseException ex) {
      log.error("[SnykClient] 이슈 조회 실패 - projectId={}, status={}", projectId, ex.getStatusCode());
      return Collections.emptyList();
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Mock (Token 없을 때 대체)
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
