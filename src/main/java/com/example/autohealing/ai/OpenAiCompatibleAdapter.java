package com.example.autohealing.ai;

import com.example.autohealing.entity.PluginConfig;
import com.example.autohealing.service.EncryptionService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

/**
 * DB 설정(PluginConfig)에 의해 런타임에 동적으로 활성화되는 OpenAI 호환 AI 어댑터.
 * OpenAI API 규격(chat/completions)을 지키는 vLLM, DeepSeek, Llama3 서버 등 어디든 연동
 * 가능합니다.
 */
@Slf4j
public class OpenAiCompatibleAdapter implements AiRemediationService {

  private final PluginConfig config;
  private final RestTemplate restTemplate;
  private final EncryptionService encryptionService;

  public OpenAiCompatibleAdapter(PluginConfig config, RestTemplate restTemplate, EncryptionService encryptionService) {
    this.config = config;
    this.restTemplate = restTemplate;
    this.encryptionService = encryptionService;
  }

  @Override
  public String providerName() {
    return config.getName() != null ? config.getName() : "OpenAiCompatible";
  }

  @Override
  @SuppressWarnings({ "unchecked", "rawtypes" })
  public AiRemediationResult fixCode(String originalCode, String vulnerabilityInfo) {
    log.info("[{}] AI 트래픽 라우팅 - 플러그인 설정 기반 동적 호출 진행", providerName());

    String plainApiKey = "";
    if (config.getApiKeyEncrypted() != null && !config.getApiKeyEncrypted().isBlank()) {
      plainApiKey = encryptionService.decrypt(config.getApiKeyEncrypted());
      if ("[DECRYPTION_FAILED]".equals(plainApiKey)) {
        log.error("[{}] API 키 복호화 실패. 원본 코드를 반환합니다.", providerName());
        return new AiRemediationResult(originalCode, "API 키 복호화 실패로 동작 중지");
      }
    }

    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    if (!plainApiKey.isBlank()) {
      // OpenAI 규격은 기본적으로 Bearer Auth를 사용
      headers.setBearerAuth(plainApiKey);
    }

    String prompt = "취약점 정보: " + vulnerabilityInfo +
        "\n\n다음 Java 코드를 보안 취약점이 해결된 안전한 코드로 수정해줘. 마크다운 언어 태그(```java 등)를 쓰지 말고 순수 코드만 반환해.\n\n" +
        originalCode;

    Map<String, Object> requestBody = Map.of(
        "model", config.getModelName() != null ? config.getModelName() : "gpt-4o",
        "messages", List.of(
            Map.of("role", "system", "content",
                "You are an expert Java security developer. Provide only fixed raw source code without markdown or explanations."),
            Map.of("role", "user", "content", prompt)),
        "temperature", 0.1);

    try {
      HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
      ResponseEntity<Map> response = restTemplate.postForEntity(config.getApiUrl(), entity, Map.class);

      if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
        List<Map<String, Object>> choices = (List<Map<String, Object>>) response.getBody().get("choices");
        if (choices != null && !choices.isEmpty()) {
          Map<String, Object> message = (Map<String, Object>) choices.get(0).get("message");
          String fixedCodeRaw = (String) message.get("content");

          log.info("[{}] AI 응답 수신 성공", providerName());
          return new AiRemediationResult(fixedCodeRaw, providerName() + " 엔진에 의한 자동 수정이 완료되었습니다.");
        }
      }
      log.warn("[{}] AI 응답이 비어있거나 올바르지 않은 형식입니다.", providerName());
    } catch (Exception e) {
      log.error("[{}] API 호출 중 치명적인 오류 발생: {}", providerName(), e.getMessage());
    }

    return new AiRemediationResult(originalCode, "AI 처리 중 오류가 발생하여 안전을 위해 원본을 유지합니다.");
  }
}
