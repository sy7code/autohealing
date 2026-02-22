package com.example.autohealing.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Snyk REST API v3 클라이언트.
 *
 * <h3>인증</h3>
 * {@code Authorization: token <SNYK_API_TOKEN>} 헤더를 사용합니다.
 *
 * <h3>주요 흐름</h3>
 * <ol>
 * <li>조직의 전체 이슈 목록 조회 ({@code /rest/orgs/{orgId}/issues})</li>
 * <li>각 이슈를 UnifiedIssue 형식으로 변환</li>
 * </ol>
 *
 * <p>
 * SNYK_API_TOKEN, SNYK_ORG_ID 은 {@code .env} 파일에 설정하세요.
 */
@Slf4j
@Component
public class SnykClient {

  private static final String SNYK_REST_BASE = "https://api.snyk.io/rest";
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

  /**
   * Snyk 조직의 모든 취약점 이슈를 수집합니다.
   *
   * @return 취약점 이슈 Map 목록 (각 Map은 개별 취약점 데이터)
   */
  @SuppressWarnings("unchecked")
  public List<Map<String, Object>> fetchVulnerabilities() {
    if (snykApiToken == null || snykApiToken.isBlank()) {
      log.warn("[SnykClient] SNYK_API_TOKEN이 설정되지 않았습니다. Mock 데이터를 반환합니다.");
      return mockVulnerabilities();
    }
    if (snykOrgId == null || snykOrgId.isBlank()) {
      log.error("[SnykClient] SNYK_ORG_ID가 설정되지 않았습니다. .env에 추가하세요.");
      return Collections.emptyList();
    }

    try {
      // Step1: REST API v3로 조직 전체 이슈 조회
      log.info("[SnykClient] REST API v3 이슈 조회 - orgId={}", snykOrgId);

      Map<String, Object> response = webClient.get()
          .uri(SNYK_REST_BASE + "/orgs/{orgId}/issues?version={ver}&limit=100",
              snykOrgId, SNYK_API_VERSION)
          .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
          .header(HttpHeaders.ACCEPT, "application/vnd.api+json")
          .retrieve()
          .bodyToMono(Map.class)
          .block();

      if (response == null) {
        log.warn("[SnykClient] 응답이 null입니다.");
        return Collections.emptyList();
      }

      List<Map<String, Object>> data = (List<Map<String, Object>>) response.get("data");
      if (data == null || data.isEmpty()) {
        log.info("[SnykClient] 이슈 없음 (data=[])");
        return Collections.emptyList();
      }

      log.info("[SnykClient] 이슈 {}건 수신", data.size());

      // REST v3 응답 → 기존 Map 형식으로 변환 (SnykParser 호환)
      return data.stream()
          .map(this::convertToLegacyFormat)
          .toList();

    } catch (WebClientResponseException ex) {
      log.error("[SnykClient] 이슈 조회 실패 - status={}, body={}",
          ex.getStatusCode(), ex.getResponseBodyAsString());
      return Collections.emptyList();
    } catch (Exception e) {
      log.error("[SnykClient] 취약점 조회 중 오류 발생", e);
      return Collections.emptyList();
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – 응답 변환 (REST v3 → 기존 SnykParser 호환 포맷)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Snyk REST v3 {@code data[]} 항목 하나를 기존 v1 parser가 읽을 수 있는 Map으로 변환합니다.
   */
  @SuppressWarnings("unchecked")
  private Map<String, Object> convertToLegacyFormat(Map<String, Object> item) {
    String id = (String) item.getOrDefault("id", "unknown");

    Map<String, Object> attributes = (Map<String, Object>) item.getOrDefault("attributes", Collections.emptyMap());

    String title = (String) attributes.getOrDefault("title", "Unknown Issue");
    String description = (String) attributes.getOrDefault("description", "");
    String severity = "";

    // severity는 effectiveSeverityLevel 또는 severity 필드
    Map<String, Object> effectiveSeverity = (Map<String, Object>) attributes.get("effective_severity_level");
    if (effectiveSeverity != null) {
      severity = (String) effectiveSeverity.getOrDefault("severity", "");
    }
    if (severity.isBlank()) {
      severity = (String) attributes.getOrDefault("severity", "medium");
    }

    // 패키지 정보
    String packageName = "";
    List<Map<String, Object>> coordinates = (List<Map<String, Object>>) attributes.get("coordinates");
    if (coordinates != null && !coordinates.isEmpty()) {
      Map<String, Object> firstCoord = coordinates.get(0);
      List<Map<String, Object>> representations = (List<Map<String, Object>>) firstCoord.get("representations");
      if (representations != null && !representations.isEmpty()) {
        Map<String, Object> dep = (Map<String, Object>) representations.get(0).get("dependency");
        if (dep != null) {
          packageName = (String) dep.getOrDefault("package_name", "");
        }
      }
    }

    return Map.of(
        "id", id,
        "title", title,
        "description", description,
        "severity", severity,
        "packageName", packageName,
        "version", "");
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
