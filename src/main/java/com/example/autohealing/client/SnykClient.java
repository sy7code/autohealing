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
import org.springframework.core.ParameterizedTypeReference;

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
public class SnykClient implements SecurityScannerService {

  // API 설정은 application.yml 에서 주입받습니다.

  private final WebClient webClient;
  private final String snykApiToken;
  private final String snykOrgId;
  private final String restBaseUrl;
  private final String v1BaseUrl;
  private final String apiVersion;

  public SnykClient(WebClient webClient,
      @Value("${snyk.api-token:}") String snykApiToken,
      @Value("${snyk.org-id:}") String snykOrgId,
      @Value("${snyk.base-url.rest:https://api.snyk.io/rest}") String restBaseUrl,
      @Value("${snyk.base-url.v1:https://api.snyk.io/v1}") String v1BaseUrl,
      @Value("${snyk.api-version:2024-10-15}") String apiVersion) {
    this.webClient = webClient;
    this.snykApiToken = snykApiToken;
    this.snykOrgId = snykOrgId;
    this.restBaseUrl = restBaseUrl;
    this.v1BaseUrl = v1BaseUrl;
    this.apiVersion = apiVersion;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public API
  // ─────────────────────────────────────────────────────────────────────────

  @Override
  public String providerName() {
    return "Snyk-REST";
  }

  @Override
  public List<Map<String, Object>> scan(String repositoryUri) {
    // repositoryUri: "sy7code/auto-healing-demo" 형식으로 들어옵니다.
    return fetchVulnerabilities(repositoryUri);
  }

  public List<Map<String, Object>> fetchVulnerabilities(String repositoryUri) {
    if (snykApiToken == null || snykApiToken.isBlank()) {
      log.warn("[SnykClient] SNYK_API_TOKEN 미설정 → Mock 데이터 반환");
      return mockVulnerabilities();
    }
    if (snykOrgId == null || snykOrgId.isBlank()) {
      log.error("[SnykClient] SNYK_ORG_ID 미설정 → .env에 추가하세요.");
      return Collections.emptyList();
    }

    try {
      // Step1: REST v3로 프로젝트 목록 조회 (현재 레포지토리 이름으로 필터링)
      List<String> projectIds = fetchProjectIds(repositoryUri);
      if (projectIds.isEmpty()) {
        log.warn("[SnykClient] 일치하는 프로젝트 없음 - repoUri={}, orgId={}", repositoryUri, snykOrgId);
        return Collections.emptyList(); // 실제 환경에서는 결과 없음으로 처리
      }
      log.info("[SnykClient] 대상 레포지토리 관련 프로젝트 {}개 발견", projectIds.size());

      // Step2: 각 프로젝트 이슈 수집 (REST v3 - 모든 타입 지원)
      return projectIds.stream()
          .flatMap(projectId -> fetchIssuesV3(projectId).stream())
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
  private List<String> fetchProjectIds(String repositoryName) {
    try {
      // "org/repo" 형태에서 "repo" 부분만 추출하여 검색 키워드로 사용
      final String searchKeyword = (repositoryName != null && repositoryName.contains("/"))
          ? repositoryName.substring(repositoryName.lastIndexOf('/') + 1)
          : repositoryName;

      // Snyk v1 API: org/{orgId}/projects (v1은 프로젝트 이름에 레포지토리 경로가 포함되어 있어 필터링 용이)
      Map<String, Object> response = webClient.get()
          .uri(v1BaseUrl + "/org/{orgId}/projects", snykOrgId)
          .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
          .header(HttpHeaders.ACCEPT, "application/json")
          .retrieve()
          .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
          })
          .block();

      if (response == null)
        return Collections.emptyList();

      List<Map<String, Object>> projects = (List<Map<String, Object>>) response.get("projects");
      if (projects == null)
        return Collections.emptyList();

      // Snyk v1 프로젝트 이름은 보통 "org/repo" 또는 "org/repo:branch" 형식으로 확실하게 대상 레포지토리를 포함합니다.
      return projects.stream()
          .filter(p -> {
            String snykProjectName = (String) p.get("name");
            
            // repositoryName 핵심 키워드가 포함되어 있는지 체크 (대소문자 무시)
            return snykProjectName != null && searchKeyword != null &&
                   snykProjectName.toLowerCase().contains(searchKeyword.toLowerCase());
          })
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
  // Private – Step2: REST v3 통합 이슈 조회 (모든 타입: vuln, code, secrets 등)
  // ─────────────────────────────────────────────────────────────────────────

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> fetchIssuesV3(String projectId) {
    try {
      log.info("[SnykClient] REST v3 통합 이슈 조회 - projectId={}", projectId);

      // Snyk REST v3 정식 파라미터: scan_item.type=project & scan_item.id={projectId}
      Map<String, Object> response = webClient.get()
          .uri(restBaseUrl + "/orgs/{orgId}/issues?version={ver}&scan_item.id={projectId}&scan_item.type=project&limit=100",
              snykOrgId, apiVersion, projectId)
          .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
          .header(HttpHeaders.ACCEPT, "application/vnd.api+json")
          .retrieve()
          .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
          })
          .block();

      if (response == null)
        return Collections.emptyList();

      List<Map<String, Object>> data = (List<Map<String, Object>>) response.get("data");
      if (data == null)
        return Collections.emptyList();

      // REST v3 응답을 SnykParserImpl이 처리할 수 있는 flat map 형식으로 변환
      List<Map<String, Object>> result = data.stream()
          .map(issue -> {
            Map<String, Object> attrs = (Map<String, Object>) issue.getOrDefault("attributes", Map.of());
            
            // v3에서는 effective_severity_level 또는 severity를 사용함
            String severity = (String) attrs.get("effective_severity_level");
            if (severity == null) {
              severity = (String) attrs.getOrDefault("severity", "medium");
            }
            
            String title = (String) attrs.getOrDefault("title", "취약점 감지됨");
            String description = (String) attrs.getOrDefault("description", "");
            String type = (String) issue.getOrDefault("type", "issue");

            // 파일 경로 추출 (v3 problems 구조 대응)
            String filePath = null;
            Object coordinates = attrs.get("coordinates");
            if (coordinates instanceof List<?> list && !list.isEmpty()) {
              Object first = list.get(0);
              if (first instanceof Map<?, ?> m) {
                 Object representation = m.get("representation");
                 if (representation instanceof List<?> reprList && !reprList.isEmpty()) {
                   filePath = reprList.get(0).toString();
                 }
              }
            }

            java.util.HashMap<String, Object> flat = new java.util.HashMap<>();
            flat.put("id", issue.getOrDefault("id", "SNYK-UNKNOWN"));
            flat.put("title", title);
            flat.put("description", description);
            flat.put("severity", severity);
            flat.put("packageName", attrs.getOrDefault("package_name", type));
            flat.put("version", attrs.getOrDefault("package_version", "unknown"));
            if (filePath != null) flat.put("file", filePath);
            
            return (Map<String, Object>) flat;
          })
          .toList();

      log.info("[SnykClient] REST v3 - projectId={} → {}건", projectId, result.size());
      return result;

    } catch (WebClientResponseException ex) {
      log.error("[SnykClient] REST v3 이슈 조회 실패 - projectId={}, status={}, body={}",
          projectId, ex.getStatusCode(), ex.getResponseBodyAsString());
      // v3 실패 시 v1으로 폴백
      return fetchIssuesV1Fallback(projectId);
    }
  }

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> fetchIssuesV1Fallback(String projectId) {
    try {
      log.info("[SnykClient] v1 폴백 이슈 조회 - projectId={}", projectId);
      Map<String, Object> response = webClient.post()
          .uri(v1BaseUrl + "/org/{orgId}/project/{projectId}/issues", snykOrgId, projectId)
          .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
          .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
          .bodyValue(Map.of("filters", Map.of(
              "severities", List.of("critical", "high", "medium"),
              "types", List.of("vuln", "license"))))
          .retrieve()
          .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
          .block();
      if (response == null) return Collections.emptyList();
      Map<String, Object> issues = (Map<String, Object>) response.get("issues");
      if (issues == null) return Collections.emptyList();
      List<Map<String, Object>> vulns = (List<Map<String, Object>>) issues.get("vulnerabilities");
      return vulns != null ? vulns : Collections.emptyList();
    } catch (Exception ex) {
      log.error("[SnykClient] v1 폴백도 실패 - projectId={}", projectId, ex);
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
