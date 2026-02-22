package com.example.autohealing.ai;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.client.RestTemplate;

/**
 * OpenAI API를 사용하는 {@link AiRemediationService} 구현체 (스텁).
 *
 * <p>
 * 현재는 Mock 응답만 반환합니다.
 * {@code OPENAI_API_KEY}를 설정하고 이 클래스에 실제 API 호출 로직을 추가하려면
 * {@code ai.type=OPENAI}로 전환하세요.
 *
 * <p>
 * 이 빈은 {@link com.example.autohealing.config.AiServiceConfig}에서 조건부로 등록됩니다.
 */
@Slf4j
public class OpenAiServiceImpl implements AiRemediationService {

  private final String apiKey;

  public OpenAiServiceImpl(RestTemplate restTemplate,
      @Value("${ai.openai.api-key:}") String apiKey) {
    this.apiKey = apiKey;
  }

  @Override
  public String providerName() {
    return "OPENAI";
  }

  @Override
  public String fixCode(String originalCode, String vulnerabilityInfo) {
    if (apiKey == null || apiKey.isBlank()) {
      log.warn("[OpenAI] OPENAI_API_KEY가 설정되지 않았습니다. Mock 수정 코드를 반환합니다.");
    } else {
      log.warn("[OpenAI] OpenAI 구현체는 현재 스텁(Stub) 상태입니다. 실제 API 호출은 미구현입니다.");
    }

    // TODO: openai-java 라이브러리 추가 후 gpt-4o API 호출 구현
    return String.format("""
        // [AUTO-HEALING OPENAI STUB] 실제 OpenAI 호출 로직 미구현
        // 취약점: %s
        // TODO: 아래 코드를 수동으로 수정해 주세요.

        %s
        """,
        vulnerabilityInfo.lines().findFirst().orElse("알 수 없는 취약점"),
        originalCode);
  }
}
