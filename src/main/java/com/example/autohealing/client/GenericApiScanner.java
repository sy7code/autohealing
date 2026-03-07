package com.example.autohealing.client;

import com.example.autohealing.entity.PluginConfig;
import com.example.autohealing.service.EncryptionService;
import com.jayway.jsonpath.JsonPath;
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
import java.util.stream.Collectors;

/**
 * DB에 저장된 PluginConfig 정보를 바탕으로 동작하는 범용 API 스캐너.
 * 코딩 없이 DB 설정만으로 새로운 외부 보안 스캐너(SaaS)를 연동합니다.
 */
public class GenericApiScanner implements SecurityScannerService {

  private static final Logger log = LoggerFactory.getLogger(GenericApiScanner.class);

  private final PluginConfig config;
  private final RestTemplate restTemplate;
  private final EncryptionService encryptionService;

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
   * JsonPath를 이용해 외부 스캐너의 고유 포맷을 내부 표준 포맷으로 변환합니다.
   */
  private List<Map<String, Object>> parseAndMapResults(String jsonResp) {
    try {
      // JsonPath.read는 List<Map<...>> 형태를 반환한다고 가정
      List<Map<String, Object>> rawVulns = JsonPath.read(jsonResp, config.getResultJsonPath());

      return rawVulns.stream().map(raw -> {
        Map<String, Object> standardVuln = new HashMap<>();

        // 식별자: config.getIdField() 기반 파싱
        Object idObj = JsonPath.read(raw, config.getIdField());
        standardVuln.put("id", idObj != null ? idObj.toString() : "UNKNOWN_ID");

        // 제목: config.getTitleField() 기반 파싱
        Object titleObj = JsonPath.read(raw, config.getTitleField());
        standardVuln.put("title", titleObj != null ? titleObj.toString() : "No Title");

        // 심각도: config.getSeverityField() 기반 파싱 및 맵핑 적용 대상
        Object severityObj = JsonPath.read(raw, config.getSeverityField());
        standardVuln.put("severity", severityObj != null ? severityObj.toString() : "medium"); // TODO:
                                                                                               // severityMappingJson 연동

        // 스캐너 이름 강제 주입
        standardVuln.put("scannerName", providerName());

        return standardVuln;
      }).collect(Collectors.toList());

    } catch (Exception e) {
      log.error("[{}] 결과 JSON 파싱 중 오류: {}", providerName(), e.getMessage());
      return Collections.emptyList();
    }
  }
}
