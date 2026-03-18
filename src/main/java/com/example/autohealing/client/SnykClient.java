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
      return mockVulnerabilities();
    }
    if (snykOrgId == null || snykOrgId.isBlank()) {
      log.error("[SnykClient] SNYK_ORG_ID 미설정");
      return Collections.emptyList();
    }

    try {
      List<String> projectIds = fetchProjectIds(repositoryUri);
      if (projectIds.isEmpty()) {
        log.warn("[SnykClient] 프로젝트를 찾지 못했습니다 - repoUri={}", repositoryUri);
        return Collections.emptyList();
      }

      return projectIds.stream()
          .flatMap(projectId -> fetchIssuesV3(projectId).stream())
          .toList();

    } catch (Exception e) {
      log.error("[SnykClient] 취약점 조회 오류", e);
      return Collections.emptyList();
    }
  }

  @SuppressWarnings("unchecked")
  private List<String> fetchProjectIds(String repositoryName) {
    List<String> allProjectIds = new ArrayList<>();
    try {
      log.info("[SnykClient] Target 탐색 시작: {}", repositoryName);

      // 1. 모든 Target을 페이지네이션으로 가져와서 수동 매칭 (인코딩/형식 이슈 방지)
      String nextUrl = restBaseUrl + "/orgs/" + snykOrgId + "/targets?version=" + apiVersion + "&limit=100";
      boolean found = false;

      while (nextUrl != null && !found) {
          log.debug("[SnykClient] Target 페이지 조회: {}", nextUrl);
          Map<String, Object> targetResp = webClient.get()
              .uri(nextUrl)
              .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
              .header(HttpHeaders.ACCEPT, "application/vnd.api+json")
              .retrieve()
              .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
              .block();

          if (targetResp == null) break;

          List<Map<String, Object>> targetData = (List<Map<String, Object>>) targetResp.get("data");
          if (targetData != null) {
              for (Map<String, Object> target : targetData) {
                  Map<String, Object> attrs = (Map<String, Object>) target.get("attributes");
                  String displayName = (attrs != null) ? (String) attrs.get("display_name") : "";

                  log.debug("[SnykClient] Target 후보: '{}'", displayName);

                  // "sy7code/autohealing-target-demo" 또는 "autohealing-target-demo" 등을 유연하게 매칭
                  if (displayName != null &&
                     (displayName.equalsIgnoreCase(repositoryName) ||
                      repositoryName.endsWith("/" + displayName) ||
                      displayName.endsWith("/" + repositoryName))) {

                      String targetId = (String) target.get("id");
                      log.info("[SnykClient] 매칭된 Target 발견! ID: {}, Name: {}", targetId, displayName);

                      // 2. 해당 Target 하위의 모든 프로젝트 수집
                      collectProjectsByTarget(targetId, allProjectIds);
                      found = true;
                  }
              }
          }

          // 다음 페이지 링크 추출
          nextUrl = null;
          Object linksObj = targetResp.get("links");
          if (linksObj instanceof Map<?, ?> links) {
              Object next = links.get("next");
              if (next instanceof String s && !s.isBlank()) {
                  // next가 상대경로면 절대경로로 변환
                  nextUrl = s.startsWith("http") ? s : "https://api.snyk.io" + s;
              }
          }
      }

      if (!found) {
          log.warn("[SnykClient] Target 전체 탐색 완료 - '{}' 와 일치하는 Target 없음", repositoryName);
      }

      // 3. (백업) 이름 기반(v1) 검색
      if (allProjectIds.isEmpty()) {
          log.info("[SnykClient] Target으로 못 찾음. v1 이름 기반 검색 시도.");
          collectProjectsByV1Name(repositoryName, allProjectIds);
      }

      log.info("[SnykClient] 최종 수집된 프로젝트 수: {}", allProjectIds.size());
      return allProjectIds.stream().distinct().toList();

    } catch (Exception ex) {
      log.error("[SnykClient] 프로젝트 탐색 오류", ex);
      return Collections.emptyList();
    }
  }

  @SuppressWarnings("unchecked")
  private void collectProjectsByTarget(String targetId, List<String> allProjectIds) {
      try {
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
                      allProjectIds.add((String) p.get("id"));
                      Map<String, Object> attrs = (Map<String, Object>) p.get("attributes");
                      log.info("[SnykClient] ✅ 프로젝트 수집: {}", (attrs != null) ? attrs.get("name") : p.get("id"));
                  }
              }
          }
      } catch (Exception e) {
          log.error("[SnykClient] Target별 프로젝트 수집 오류", e);
      }
  }

  @SuppressWarnings("unchecked")
  private void collectProjectsByV1Name(String repositoryName, List<String> allProjectIds) {
      try {
          final String keyword = repositoryName.contains("/") ? repositoryName.substring(repositoryName.lastIndexOf('/') + 1) : repositoryName;
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
                      if (pname != null && pname.toLowerCase().contains(keyword.toLowerCase())) {
                          allProjectIds.add((String) p.get("id"));
                          log.info("[SnykClient] ✅ v1 매칭 성공: {}", pname);
                      }
                  }
              }
          }
      } catch (Exception e) {
          log.error("[SnykClient] v1 검색 오류", e);
      }
  }

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> fetchIssuesV3(String projectId) {
    try {
      log.info("[SnykClient] 이슈 조회 (v3): {}", projectId);
      Map<String, Object> response = webClient.get()
          .uri(restBaseUrl + "/orgs/{orgId}/issues?version={ver}&scan_item.id={projectId}&scan_item.type=project",
              snykOrgId, apiVersion, projectId)
          .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
          .header(HttpHeaders.ACCEPT, "application/vnd.api+json")
          .retrieve()
          .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
          .block();

      if (response == null || response.get("data") == null) return Collections.emptyList();
      List<Map<String, Object>> data = (List<Map<String, Object>>) response.get("data");

      return data.stream()
          .map(issue -> {
            Map<String, Object> attrs = (Map<String, Object>) issue.getOrDefault("attributes", Map.of());
            String severity = (String) attrs.get("effective_severity_level");
            if (severity == null) severity = (String) attrs.getOrDefault("severity", "medium");

            java.util.HashMap<String, Object> flat = new java.util.HashMap<>();
            flat.put("id", issue.getOrDefault("id", "SNYK-UNKNOWN"));
            flat.put("title", attrs.getOrDefault("title", "취약점"));
            flat.put("description", attrs.getOrDefault("description", ""));
            flat.put("severity", severity);
            
            // 파일 경로 추출 (Snyk REST API v3)
            // Code analysis(SAST): coordinates[0].representations[0].source_location.file_path
            // Open Source(SCA): 파일 경로 없음 (build.gradle 등은 SnykParser에서 처리)
            Object coordinates = attrs.get("coordinates");
            if (coordinates instanceof List<?> coordList && !coordList.isEmpty()) {
                Map<String, Object> firstCoord = (Map<String, Object>) coordList.get(0);

                // 1순위: representations[0].source_location.file_path (v3 SAST 표준)
                Object representationsObj = firstCoord.get("representations");
                if (representationsObj instanceof List<?> repList && !repList.isEmpty()) {
                    Map<String, Object> firstRep = (Map<String, Object>) repList.get(0);
                    Object srcLoc = firstRep.get("source_location");
                    if (srcLoc instanceof Map<?, ?> srcLocMap) {
                        Object filePath = srcLocMap.get("file_path");
                        if (filePath != null && !filePath.toString().isBlank()) {
                            flat.put("file", filePath.toString());
                            log.debug("[SnykClient] 파일 경로 추출 성공 (source_location): {}", filePath);
                        }
                    }
                    // 2순위: representations[0].resource_path
                    if (!flat.containsKey("file")) {
                        Object resourcePath = firstRep.get("resource_path");
                        if (resourcePath != null && !resourcePath.toString().isBlank()) {
                            flat.put("file", resourcePath.toString());
                            log.debug("[SnykClient] 파일 경로 추출 성공 (resource_path): {}", resourcePath);
                        }
                    }
                }

                // 3순위: 구버전 단수형 representation[0] (하위 호환)
                if (!flat.containsKey("file")) {
                    Object representationObj = firstCoord.get("representation");
                    if (representationObj instanceof List<?> oldRepList && !oldRepList.isEmpty()) {
                        String val = oldRepList.get(0).toString();
                        if (!val.isBlank()) {
                            flat.put("file", val);
                            log.debug("[SnykClient] 파일 경로 추출 성공 (representation 구버전): {}", val);
                        }
                    }
                }

                if (!flat.containsKey("file")) {
                    log.warn("[SnykClient] 파일 경로 추출 실패 - issueId={}", flat.get("id"));
                }
            }
            return (Map<String, Object>) flat;
          })
          .toList();
    } catch (Exception ex) {
      log.error("[SnykClient] 이슈 조회 오류 - {}", projectId);
      return Collections.emptyList();
    }
  }

  private List<Map<String, Object>> mockVulnerabilities() {
    return List.of(Map.of("id", "MOCK-1", "title", "Mock Vuln", "severity", "high"));
  }
}
