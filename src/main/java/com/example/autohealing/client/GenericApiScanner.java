package com.example.autohealing.client;

import com.example.autohealing.entity.PluginConfig;
import com.example.autohealing.service.EncryptionService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * DB에 저장된 PluginConfig 정보를 바탕으로 동작하는 범용 API 스캐너.
 * 코딩 없이 DB 설정만으로 새로운 외부 보안 스캐너(SaaS)를 연동합니다.
 */
public class GenericApiScanner implements SecurityScannerService {

  private static final Logger log = LoggerFactory.getLogger(GenericApiScanner.class);

  private final PluginConfig config;
  private final RestTemplate restTemplate;
  private final EncryptionService encryptionService;
  private final ObjectMapper objectMapper = new ObjectMapper();

  public GenericApiScanner(PluginConfig config, RestTemplate restTemplate, EncryptionService encryptionService) {
    this.config = config;
    this.restTemplate = restTemplate;
    this.encryptionService = encryptionService;
  }

  @Override
  public String providerName() {
    return config.getName();
  }

  @Override
  public List<Map<String, Object>> scan(String repositoryUri) {
    log.info("[{}] 스캔 시작 - 대상: {}", providerName(), repositoryUri);

    try {
      // 1. 헤더 설정 및 인증 처리
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

      String plainApiKey = encryptionService.decrypt(config.getApiKeyEncrypted());
      if ("[DECRYPTION_FAILED]".equals(plainApiKey)) {
        log.error("[{}] 스캐너 API Key 복호화 실패. 스캔을 중단합니다.", providerName());
        return Collections.emptyList();
      }

      if (config.getAuthType() == PluginConfig.AuthType.BEARER) {
        headers.setBearerAuth(plainApiKey);
      } else if (config.getAuthType() == PluginConfig.AuthType.HEADER) {
        headers.set(config.getAuthHeaderName(), plainApiKey);
      } else if (config.getAuthType() == PluginConfig.AuthType.BASIC) {
        headers.setBasicAuth("", plainApiKey);
      }

      // 2. 외부 API 호출
      // SSRF 방어를 위해 향후 URL 유효성 검사 등 부트로직 추가 필요
      HttpEntity<String> entity = new HttpEntity<>(headers);
      HttpMethod method = HttpMethod.valueOf(config.getHttpMethod());

      log.debug("[{}] API 호출: {} {}", providerName(), method, config.getApiUrl());
      ResponseEntity<String> response = restTemplate.exchange(config.getApiUrl(), method, entity, String.class);

      if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
        log.error("[{}] API 호출 실패. 상태코드: {}", providerName(), response.getStatusCode());
        return Collections.emptyList();
      }

      // 3. JSON 응답 파싱 및 표준화 맵핑
      String jsonResp = response.getBody();
      return parseAndMapResults(jsonResp);

    } catch (Exception e) {
      log.error("[{}] 스캔 중 오류 발생: {}", providerName(), e.getMessage());
      return Collections.emptyList(); // 무시하고 진행
    }
  }

  /**
   * ObjectMapper를 이용해 외부 스캐너의 고유 포맷을 내부 표준 포맷으로 변환합니다.
   * JsonPath 대체 로직 적용.
   */
  private List<Map<String, Object>> parseAndMapResults(String jsonResp) {
    try {
      JsonNode rootNode = objectMapper.readTree(jsonResp);
      JsonNode vulnsNode = extractNodeByPath(rootNode, config.getResultJsonPath());

      if (vulnsNode == null || !vulnsNode.isArray()) {
        log.warn("[{}] 결과 배열을 찾을 수 없습니다. JsonPath: {}", providerName(), config.getResultJsonPath());
        return Collections.emptyList();
      }

      List<Map<String, Object>> mappedResults = new java.util.ArrayList<>();

      for (JsonNode vulnRaw : vulnsNode) {
        Map<String, Object> standardVuln = new HashMap<>();

        // 식별자
        JsonNode idNode = extractNodeByPath(vulnRaw, config.getIdField());
        standardVuln.put("id", (idNode != null && !idNode.isNull()) ? idNode.asText() : "UNKNOWN_ID");

        // 제목
        JsonNode titleNode = extractNodeByPath(vulnRaw, config.getTitleField());
        standardVuln.put("title", (titleNode != null && !titleNode.isNull()) ? titleNode.asText() : "No Title");

        // 심각도
        JsonNode severityNode = extractNodeByPath(vulnRaw, config.getSeverityField());
        standardVuln.put("severity",
            (severityNode != null && !severityNode.isNull()) ? severityNode.asText() : "medium");

        // 스캐너 이름 강제 주입
        standardVuln.put("scannerName", providerName());

        mappedResults.add(standardVuln);
      }
      return mappedResults;

    } catch (Exception e) {
      log.error("[{}] 결과 JSON 파싱 중 오류: {}", providerName(), e.getMessage());
      return Collections.emptyList();
    }
  }

  /**
   * 점(.)으로 구분된 간단한 JsonPath 문자열을 기반으로 JsonNode를 탐색합니다.
   * 예: "data.issues" -> root.path("data").path("issues")
   */
  private JsonNode extractNodeByPath(JsonNode root, String pathExpression) {
    if (root == null || pathExpression == null || pathExpression.isBlank()) {
      return root;
    }

    // "$." 로 시작하는 경우 제거
    if (pathExpression.startsWith("$.")) {
      pathExpression = pathExpression.substring(2);
    } else if (pathExpression.startsWith("$")) {
      pathExpression = pathExpression.substring(1);
    }

    JsonNode current = root;
    String[] parts = pathExpression.split("\\.");
    for (String part : parts) {
      if (part.isBlank())
        continue;

      if (part.contains("[") && part.contains("]")) {
        // 배열 인덱스가 포함된 경우 (예: "items[0]")
        int bracketStart = part.indexOf('[');
        int bracketEnd = part.indexOf(']');
        String propName = part.substring(0, bracketStart);
        String indexStr = part.substring(bracketStart + 1, bracketEnd);

        if (!propName.isEmpty()) {
          current = current.path(propName);
        }
        if ("*".equals(indexStr)) {
          // 별표인 경우 우선 그대로 반환 (이 구현에서는 가장 바깥쪽 배열에 사용하는 용도)
          return current;
        } else {
          try {
            int idx = Integer.parseInt(indexStr);
            current = current.path(idx);
          } catch (NumberFormatException e) {
            // 잘못된 인덱스
          }
        }
      } else {
        current = current.path(part);
      }

      if (current.isMissingNode()) {
        return null;
      }
    }
    return current;
  }
}
