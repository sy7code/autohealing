package com.example.autohealing.ai;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

/**
 * Gemini API를 사용하는 {@link AiRemediationService} 기본 구현체.
 *
 * <h3>사용 모델</h3>
 * {@code gemini-1.5-flash} (기본값, application.yml에서 변경 가능)
 *
 * <h3>API 인증</h3>
 * {@code ?key=GEMINI_API_KEY} 쿼리 파라미터 방식
 *
 * <h3>Fallback</h3>
 * {@code GEMINI_API_KEY}가 없으면 원본 코드에 보안 주석을 추가하여 반환합니다 (Mock 모드).
 *
 * <p>
 * 이 빈은 {@link com.example.autohealing.config.AiServiceConfig}에서 조건부로 등록됩니다.
 */
@Slf4j
public class GeminiAiServiceImpl implements AiRemediationService {

  private static final String GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={apiKey}";

  private final RestTemplate restTemplate;
  private final String apiKey;
  private final String model;

  public GeminiAiServiceImpl(RestTemplate restTemplate,
      @Value("${ai.gemini.api-key:}") String apiKey,
      @Value("${ai.gemini.model:gemini-1.5-flash}") String model) {
    this.restTemplate = restTemplate;
    this.apiKey = apiKey;
    this.model = model;
  }

  @Override
  public String providerName() {
    return "GEMINI";
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public API
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Gemini API로 취약한 코드를 수정합니다.
   *
   * @param originalCode      원본 소스 코드
   * @param vulnerabilityInfo 취약점 요약 정보
   * @return 수정된 소스 코드 (API 실패 시 원본 반환)
   */
  @Override
  public String fixCode(String originalCode, String vulnerabilityInfo) {
    if (apiKey == null || apiKey.isBlank()) {
      log.warn("[GeminiAI] GEMINI_API_KEY가 설정되지 않았습니다. Mock 수정 코드를 반환합니다.");
      return mockFixedCode(originalCode, vulnerabilityInfo);
    }

    log.info("[GeminiAI] 코드 수정 요청 시작 (model={})", model);
    try {
      String prompt = buildPrompt(originalCode, vulnerabilityInfo);
      String rawResponse = callGeminiApi(prompt);
      String fixedCode = extractCodeFromResponse(rawResponse);

      log.info("[GeminiAI] 코드 수정 완료 (응답 길이={}자)", fixedCode.length());
      return fixedCode;

    } catch (Exception e) {
      log.error("[GeminiAI] API 호출 실패 - 원본 코드를 반환합니다.", e);
      return originalCode;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – API Call
  // ─────────────────────────────────────────────────────────────────────────

  @SuppressWarnings("unchecked")
  private String callGeminiApi(String prompt) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);

    // Gemini API 요청 바디
    Map<String, Object> requestBody = Map.of(
        "contents", List.of(
            Map.of("parts", List.of(
                Map.of("text", prompt)))),
        "generationConfig", Map.of(
            "temperature", 0.2, // 낮은 값 = 더 결정론적 출력
            "maxOutputTokens", 8192));

    HttpEntity<Map<String, Object>> request = new HttpEntity<>(requestBody, headers);

    ResponseEntity<Map> response = restTemplate.exchange(
        GEMINI_API_URL,
        HttpMethod.POST,
        request,
        Map.class,
        model, apiKey);

    if (response.getBody() == null) {
      throw new IllegalStateException("Gemini API 응답 바디가 비어있습니다.");
    }

    // candidates[0].content.parts[0].text 추출
    List<Map<String, Object>> candidates = (List<Map<String, Object>>) response.getBody().get("candidates");
    Map<String, Object> content = (Map<String, Object>) candidates.get(0).get("content");
    List<Map<String, Object>> parts = (List<Map<String, Object>>) content.get("parts");
    return (String) parts.get(0).get("text");
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – Helpers
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Gemini에게 전달할 보안 수정 프롬프트를 생성합니다.
   */
  private String buildPrompt(String originalCode, String vulnerabilityInfo) {
    return String.format("""
        You are an expert security engineer. Your task is to fix a security vulnerability in the provided source code.

        ## Vulnerability Information
        %s

        ## Original Source Code
        ```
        %s
        ```

        ## Instructions
        1. Analyze the vulnerability described above
        2. Fix ONLY the vulnerable part while keeping the rest of the code unchanged
        3. Return the COMPLETE fixed source code (not just the changed lines)
        4. Wrap the fixed code in a single ```java code block
        5. Do NOT include any explanation outside the code block
        """, vulnerabilityInfo, originalCode);
  }

  /**
   * AI 응답 텍스트에서 코드 블록(```...```)을 추출합니다.
   * 코드 블록이 없으면 전체 응답을 반환합니다.
   */
  private String extractCodeFromResponse(String response) {
    if (response == null || response.isBlank())
      return "";

    // ```java ... ``` 또는 ``` ... ``` 패턴 추출
    int startIdx = response.indexOf("```");
    if (startIdx == -1)
      return response.trim();

    int codeStart = response.indexOf('\n', startIdx) + 1;
    int endIdx = response.lastIndexOf("```");
    if (endIdx <= codeStart)
      return response.trim();

    return response.substring(codeStart, endIdx).trim();
  }

  /**
   * API key 없을 때 반환하는 Mock 수정 코드.
   * 원본 코드 첫 줄 위에 TODO 보안 주석을 추가합니다.
   */
  private String mockFixedCode(String originalCode, String vulnerabilityInfo) {
    return String.format("""
        // [AUTO-HEALING MOCK] GEMINI_API_KEY 미설정 - 수동 수정 필요
        // 보안 취약점: %s
        // TODO: 아래 코드의 취약점을 수동으로 수정해 주세요.

        %s
        """,
        vulnerabilityInfo.lines().findFirst().orElse("알 수 없는 취약점"),
        originalCode);
  }
}
