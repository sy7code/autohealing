package com.example.autohealing.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.springframework.core.ParameterizedTypeReference;

/**
 * Snyk REST API 클라이언트 (legacy - 무료 플랜 환경에서는 비활성화됨).
 *
 * <p>Snyk 무료 플랜에서는 REST API v3의 /projects, /issues 엔드포인트가 403을 반환합니다.
 * 이 클라이언트는 {@code plugin.use-static-defaults=true}일 때만 활성화됩니다.
 *
 * <p><b>운영 환경 권장 방식:</b> GitHub Actions에서 Snyk CLI를 실행하고
 * 결과를 {@code POST /api/webhook/snyk}으로 전송하는 방식을 사용하세요.
 *
 * @see com.example.autohealing.controller.SnykWebhookController
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "plugin.use-static-defaults", havingValue = "true", matchIfMissing = true)
public class SnykClient implements SecurityScannerService {

  private final WebClient webClient;
  private final String snykApiToken;
  private final String snykOrgId;
  private final String restBaseUrl;
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

  /**
   * Snyk REST API v3에서 취약점을 조회합니다.
   *
   * <p>전략: Org 전체 이슈를 조회합니다.
   * 무료 플랜에서는 /projects 403, scan_item.type=target 미지원이므로
   * 필터 없이 전체 조회 후 반환합니다.
   */
  public List<Map<String, Object>> fetchVulnerabilities(String repositoryUri) {
    if (snykApiToken == null || snykApiToken.isBlank()) {
      log.warn("[SnykClient] SNYK_API_TOKEN 미설정 - mock 데이터 반환");
      return mockVulnerabilities();
    }
    if (snykOrgId == null || snykOrgId.isBlank()) {
      log.error("[SnykClient] SNYK_ORG_ID 미설정");
      return Collections.emptyList();
    }

    try {
      log.info("[SnykClient] === Snyk 취약점 조회 시작 === repo={}", repositoryUri);

      // Org 전체 이슈 조회 (필터 없음 - 무료 플랜 호환)
      List<Map<String, Object>> allIssues = fetchAllOrgIssues();

      log.info("[SnykClient] === Snyk 취약점 조회 완료 === 총 {}건", allIssues.size());
      return allIssues;

    } catch (Exception e) {
      log.error("[SnykClient] 취약점 조회 오류", e);
      return Collections.emptyList();
    }
  }

  /**
   * Org 전체 이슈를 페이지네이션으로 조회합니다.
   * /orgs/{orgId}/issues?version=... (필터 없음)
   */
  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> fetchAllOrgIssues() {
    List<Map<String, Object>> allIssues = new ArrayList<>();

    String nextUrl = restBaseUrl + "/orgs/" + snykOrgId
        + "/issues?version=" + apiVersion
        + "&limit=100";

    int pageCount = 0;

    while (nextUrl != null) {
      pageCount++;
      log.info("[SnykClient] 이슈 조회 페이지 {} - URL: {}", pageCount, nextUrl);

      try {
        Map<String, Object> response = webClient.get()
            .uri(nextUrl)
            .header(HttpHeaders.AUTHORIZATION, "token " + snykApiToken)
            .header(HttpHeaders.ACCEPT, "application/vnd.api+json")
            .retrieve()
            .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
            .block();

        if (response == null) {
          log.warn("[SnykClient] API 응답 null - 중단");
          break;
        }

        Object dataObj = response.get("data");
        if (dataObj == null) {
          log.warn("[SnykClient] data 필드 없음 - 응답 키: {}", response.keySet());
          break;
        }

        List<Map<String, Object>> data = (List<Map<String, Object>>) dataObj;
        log.info("[SnykClient] 페이지 {} 이슈 수신: {}건", pageCount, data.size());

        for (Map<String, Object> issue : data) {
          Map<String, Object> flat = flattenIssue(issue);
          allIssues.add(flat);
          log.info("[SnykClient]   이슈 수집: id={}, severity={}, title={}, file={}",
              flat.get("id"), flat.get("severity"), flat.get("title"), flat.getOrDefault("file", "N/A"));
        }

        // 다음 페이지
        nextUrl = null;
        Object linksObj = response.get("links");
        if (linksObj instanceof Map<?, ?> links) {
          Object next = links.get("next");
          if (next instanceof String s && !s.isBlank()) {
            nextUrl = s.startsWith("http") ? s : "https://api.snyk.io" + s;
          }
        }

      } catch (Exception ex) {
        log.error("[SnykClient] 이슈 조회 중 예외 발생 (페이지 {})", pageCount, ex);
        break;
      }
    }

    log.info("[SnykClient] 전체 이슈 수집 완료: {}건 ({}페이지)", allIssues.size(), pageCount);
    return allIssues;
  }

  /**
   * Snyk REST v3 이슈 응답 객체를 플랫 Map으로 변환합니다.
   */
  @SuppressWarnings("unchecked")
  private Map<String, Object> flattenIssue(Map<String, Object> issue) {
    Map<String, Object> attrs = (Map<String, Object>) issue.getOrDefault("attributes", Map.of());
    String severity = (String) attrs.get("effective_severity_level");
    if (severity == null) severity = (String) attrs.getOrDefault("severity", "medium");

    java.util.HashMap<String, Object> flat = new java.util.HashMap<>();
    flat.put("id", issue.getOrDefault("id", "SNYK-UNKNOWN"));
    flat.put("title", attrs.getOrDefault("title", "취약점"));
    flat.put("description", attrs.getOrDefault("description", ""));
    flat.put("severity", severity);
    flat.put("scannerName", "SNYK");

    // 파일 경로 추출 (Snyk REST API v3)
    Object coordinates = attrs.get("coordinates");
    if (coordinates instanceof List<?> coordList && !coordList.isEmpty()) {
      Map<String, Object> firstCoord = (Map<String, Object>) coordList.get(0);

      // 1순위: representations[0].source_location.file_path (v3 SAST/Code Analysis 표준)
      Object representationsObj = firstCoord.get("representations");
      if (representationsObj instanceof List<?> repList && !repList.isEmpty()) {
        Map<String, Object> firstRep = (Map<String, Object>) repList.get(0);
        Object srcLoc = firstRep.get("source_location");
        if (srcLoc instanceof Map<?, ?> srcLocMap) {
          Object filePath = srcLocMap.get("file_path");
          if (filePath != null && !filePath.toString().isBlank()) {
            flat.put("file", filePath.toString());
          }
        }
        // 2순위: representations[0].resource_path
        if (!flat.containsKey("file")) {
          Object resourcePath = firstRep.get("resource_path");
          if (resourcePath != null && !resourcePath.toString().isBlank()) {
            flat.put("file", resourcePath.toString());
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
          }
        }
      }
    }

    return flat;
  }

  private List<Map<String, Object>> mockVulnerabilities() {
    return List.of(Map.of("id", "MOCK-1", "title", "Mock Vuln", "severity", "high"));
  }
}
