package com.example.autohealing.config;

import com.example.autohealing.ai.AiRemediationService;
import com.example.autohealing.ai.GeminiAiServiceImpl;
import com.example.autohealing.ai.OpenAiServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

/**
 * AI 코드 수정 엔진 설정.
 *
 * <p>
 * {@code application.yml}의 {@code ai.type} 값에 따라 적절한 구현체를 빈으로 등록합니다.
 *
 * <h3>전환 방법</h3>
 * 
 * <pre>
 * # Gemini 사용 (기본값)
 * ai:
 *   type: GEMINI
 *
 * # OpenAI로 전환
 * ai:
 *   type: OPENAI
 * </pre>
 *
 * <h3>새 AI 모델 추가 방법</h3>
 * <ol>
 * <li>{@link AiRemediationService}를 구현하는 새 클래스 작성</li>
 * <li>이 Config 클래스에 {@code @ConditionalOnProperty}를 붙인 {@code @Bean} 메서드
 * 추가</li>
 * <li>{@code application.yml}에 새 타입 추가</li>
 * </ol>
 */
@Slf4j
@Configuration
public class AiServiceConfig {

  /**
   * Gemini AI 서비스 빈.
   * {@code ai.type=GEMINI}이거나 {@code ai.type}이 설정되지 않은 경우(기본값) 사용됩니다.
   */
  @Bean
  @ConditionalOnProperty(name = "ai.type", havingValue = "GEMINI", matchIfMissing = true)
  public AiRemediationService geminiAiService(
      RestTemplate restTemplate,
      @Value("${ai.gemini.api-key:}") String apiKey,
      @Value("${ai.gemini.model:gemini-1.5-flash}") String model) {

    log.info("[AiServiceConfig] AI 엔진 등록: GEMINI (model={})", model);
    if (apiKey.isBlank()) {
      log.warn("[AiServiceConfig] GEMINI_API_KEY 미설정 - Mock 모드로 동작합니다.");
    }
    return new GeminiAiServiceImpl(restTemplate, apiKey, model);
  }

  /**
   * OpenAI 서비스 빈.
   * {@code ai.type=OPENAI}일 때 사용됩니다.
   */
  @Bean
  @ConditionalOnProperty(name = "ai.type", havingValue = "OPENAI")
  public AiRemediationService openAiService(
      RestTemplate restTemplate,
      @Value("${ai.openai.api-key:}") String apiKey) {

    log.info("[AiServiceConfig] AI 엔진 등록: OPENAI");
    if (apiKey.isBlank()) {
      log.warn("[AiServiceConfig] OPENAI_API_KEY 미설정 - Stub 모드로 동작합니다.");
    }
    return new OpenAiServiceImpl(restTemplate, apiKey);
  }
}
