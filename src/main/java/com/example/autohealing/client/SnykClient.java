package com.example.autohealing.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.springframework.core.ParameterizedTypeReference;

/**
 * Snyk 클라이언트 (REST v3 + v1 혼합 전략).
 *
 * <pre>
 * v20 개선: '이름 기반 검색'에서 'Target(레포지토리) 소속 기반 검색'으로 변경.
 * Snyk Code 프로젝트가 "Code analysis"라는 공통 이름을 가져도 정확히 찾아냅니다.
 * </pre>
 */
@Slf4j
@Component
public class SnykClient implements SecurityScannerService {

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

  @Override
  public String providerName() {
    return "Snyk-REST";
  }

  @Override
  public List<Map<String, Object>> scan(String repositoryUri) {
    return fetchVulnerabilities(repositoryUri);
  }

  public List<Map<String, Object>> fetchVulnerabilities(String repositoryUri) {
    if (snykApiToken == null || snykApiToken.isBlank()) {
      log.warn("[SnykClient] SNYK_API_TOKEN 미설정 → Mock 데이터 반환");
      return mockVulnerabilities();
    }
    if (snykOrgId == null || snykOrgId.isBlank()) {
      log.error("[SnykClient] SNYK_ORG_ID 미설정");
      return Collections.emptyList();
    }

    try {
      // Step1: Target ID를 먼저 찾고 해당 Target 소속 프로젝트들을 수집
      List<String> projectIds = fetchProjectIds(repositoryUri);
      if (projectIds.isEmpty()) {
        log.warn("[SnykClient] 일치하는 프로젝트 없음 - repoUri={}", repositoryUri);
        return Collections.emptyList();
      }
      log.info("[SnykClient] 대상 레포지토리 관련 프로젝트 {}개 발견", projectIds.size());

      // Step2: 각 프로젝트 이슈 수집 (REST v3)
      return projectIds.stream()
          .flatMap(projectId -> fetchIssuesV3(projectId).stream())
          .toList();

    } catch (Exception e) {
      log.error("[SnykClient] 취약점 조회 오류", e);
      return Collections.emptyList();
    }
  }

  /**
   * 레포지토리 이름을 통해 Snyk Target ID를 찾고, 그에 속한 모든 프로젝트 ID를 반환합니다.
   */
  @SuppressWarnings("unchecked")
  private List<String> fetchProjectIds(String repositoryName) {
    List<String> allProjectIds = new ArrayList<>();
    try {
      log.info("[SnykClient] Target 기반 프로젝트 탐지 시작: {}", repositoryName);

      // 1. Snyk REST v3: 이 레포지토리(Target)의 고유 ID 찾기
      Map<String, Object> targetResp = webClient.get()
          .uri(restBaseUrl + "/orgs/{orgId}/targets?version={ver}&display_name={repoName}",
              snykOrgId, apiVersion, repositoryName)
          .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
          .header(HttpHeaders.ACCEPT, "application/vnd.api+json")
          .retrieve()
          .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
          .block();

      if (targetResp != null) {
          List<Map<String, Object>> targetData = (List<Map<String, Object>>) targetResp.get("data");
          if (targetData != null && !targetData.isEmpty()) {
              for (Map<String, Object> target : targetData) {
                  String targetId = (String) target.get("id");
                  log.info("[SnykClient] Target 발견 - ID: {}, Name: {}", targetId, repositoryName);

                  // 2. 해당 Target에 속한 모든 프로젝트 가져오기
                  Map<String, Object> projResp = webClient.get()
                      .uri(restBaseUrl + "/orgs/{orgId}/projects?version={ver}&target_id={targetId}&limit=100",
                          snykOrgId, apiVersion, targetId)
                      .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
                      .header(HttpHeaders.ACCEPT, "application/vnd.api+json")
                      .retrieve()
                      .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                      .block();

                  if (projResp != null) {
                      List<Map<String, Object>> projData = (List<Map<String, Object>>) projResp.get("data");
                      if (projData != null) {
                          for (Map<String, Object> p : projData) {
                              String pid = (String) p.get("id");
                              Map<String, Object> attrs = (Map<String, Object>) p.get("attributes");
                              String pname = (attrs != null) ? (String) attrs.get("name") : "unknown";
                              log.info("[SnykClient] ✅ 프로젝트 매칭(Target소속): {} (ID: {})", pname, pid);
                              allProjectIds.add(pid);
                          }
                      }
                  }
              }
          }
      }

      // 3. (백업) 이름 기반(v1) 검색 병행
      if (allProjectIds.isEmpty()) {
          log.info("[SnykClient] Target으로 발견된 프로젝트가 없음. 이름 기반(v1) 검색을 수행합니다.");
          final String searchKeyword = (repositoryName != null && repositoryName.contains("/"))
              ? repositoryName.substring(repositoryName.lastIndexOf('/') + 1)
              : repositoryName;

          Map<String, Object> v1Resp = webClient.get()
              .uri(v1BaseUrl + "/org/{orgId}/projects", snykOrgId)
              .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
              .header(HttpHeaders.ACCEPT, "application/json")
              .retrieve()
              .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
              .block();

          if (v1Resp != null) {
              List<Map<String, Object>> v1Projects = (List<Map<String, Object>>) v1Resp.get("projects");
              if (v1Projects != null) {
                  for (Map<String, Object> p : v1Projects) {
                      String pname = (String) p.get("name");
                      String pid = (String) p.get("id");
                      if (pname != null && searchKeyword != null && pname.toLowerCase().contains(searchKeyword.toLowerCase())) {
                          log.info("[SnykClient] ✅ 프로젝트 매칭(이름기준): {} (ID: {})", pname, pid);
                          allProjectIds.add(pid);
                      }
                  }
              }
          }
      }

      log.info("[SnykClient] 최종 탐지 결과: 총 {}개의 프로젝트 ID 수집됨", allProjectIds.size());
      return allProjectIds.stream().distinct().toList();

    } catch (Exception ex) {
      log.error("[SnykClient] 프로젝트 탐지 중 오류 발생 - repo={}", repositoryName, ex);
      return Collections.emptyList();
    }
  }

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> fetchIssuesV3(String projectId) {
    try {
      log.info("[SnykClient] REST v3 통합 이슈 조회 - projectId={}", projectId);

      Map<String, Object> response = webClient.get()
          .uri(restBaseUrl + "/orgs/{orgId}/issues?version={ver}&scan_item.id={projectId}&scan_item.type=project&limit=100",
              snykOrgId, apiVersion, projectId)
          .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
          .header(HttpHeaders.ACCEPT, "application/vnd.api+json")
          .retrieve()
          .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
          .block();

      if (response == null) return Collections.emptyList();
      List<Map<String, Object>> data = (List<Map<String, Object>>) response.get("data");
      if (data == null) return Collections.emptyList();

      return data.stream()
          .map(issue -> {
            Map<String, Object> attrs = (Map<String, Object>) issue.getOrDefault("attributes", Map.of());
            String severity = (String) attrs.get("effective_severity_level");
            if (severity == null) severity = (String) attrs.getOrDefault("severity", "medium");
            
            String title = (String) attrs.getOrDefault("title", "취약점 감지됨");
            String description = (String) attrs.getOrDefault("description", "");
            
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
            flat.put("packageName", attrs.getOrDefault("package_name", issue.getOrDefault("type", "issue")));
            flat.put("version", attrs.getOrDefault("package_version", "unknown"));
            if (filePath != null) flat.put("file", filePath);
            
            return (Map<String, Object>) flat;
          })
          .toList();

    } catch (WebClientResponseException ex) {
      log.error("[SnykClient] REST v3 이슈 조회 실패 - projectId={}, status={}", projectId, ex.getStatusCode());
      return fetchIssuesV1Fallback(projectId);
    } catch (Exception ex) {
      log.error("[SnykClient] 이슈 조회 중 예기치 않은 오류 - projectId={}", projectId, ex);
      return Collections.emptyList();
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
      log.error("[SnykClient] v1 폴백 실패 - projectId={}", projectId, ex);
      return Collections.emptyList();
    }
  }

  private List<Map<String, Object>> mockVulnerabilities() {
    return List.of(
        Map.of("id", "MOCK-1", "title", "Mock Critical Vuln", "severity", "critical"),
        Map.of("id", "MOCK-2", "title", "Mock High Vuln", "severity", "high")
    );
  }
}
