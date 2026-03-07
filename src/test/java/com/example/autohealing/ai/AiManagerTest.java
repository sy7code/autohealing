package com.example.autohealing.ai;

import com.example.autohealing.entity.PluginConfig;
import com.example.autohealing.repository.PluginConfigRepository;
import com.example.autohealing.service.EncryptionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.context.ApplicationContext;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

class AiManagerTest {

  @Mock
  private ApplicationContext context;
  @Mock
  private PluginConfigRepository configRepository;
  @Mock
  private EncryptionService encryptionService;
  @Mock
  private RestTemplate restTemplate;

  private CodeSanitizer codeSanitizer = new CodeSanitizer();
  private AiManager aiManager;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  @DisplayName("다중 AI 엔진 체인 생성 및 정상 응답 (Fallback 성공) 검증")
  void testAiManagerFallbackChain() {
    // given: PluginConfig에 1개의 동적 엔진 등록 (하지만 API 호출 실패/원본 반환 시나리오 가정)
    PluginConfig dynamicConfig = new PluginConfig();
    dynamicConfig.setName("Dynamic OpenAI");
    dynamicConfig.setPluginType(PluginConfig.PluginType.AI_ENGINE);
    dynamicConfig.setEnabled(true);
    dynamicConfig.setApiKeyEncrypted("enc_key");

    when(configRepository.findByPluginTypeAndEnabledTrue(PluginConfig.PluginType.AI_ENGINE))
        .thenReturn(List.of(dynamicConfig));
    // 동적 엔진은 RestTemplate 호출 실패로 원본 코드를 반환한다고 가정 (여기서는 Stub으로 간주하여 실패 유도)

    // given: 정적 Spring Bean(Gemini)이 성공적으로 동작 유도
    AiRemediationService mockStaticGemini = new AiRemediationService() {
      @Override
      public String providerName() {
        return "GEMINI";
      }

      @Override
      public AiRemediationResult fixCode(String originalCode, String vulnInfo) {
        return new AiRemediationResult("```java\nSystem.out.println(\"Fixed\");\n```", "Gemini Fixed");
      }
    };

    when(context.getBeansOfType(AiRemediationService.class))
        .thenReturn(Map.of("gemini", mockStaticGemini));

    aiManager = new AiManager(context, configRepository, encryptionService, restTemplate, codeSanitizer);

    // when
    AiRemediationResult result = aiManager.fixCode("System.out.println(\"Vuln\");", "Test Vuln");

    // then: 동적 엔진 실패 시 정적엔진(Gemini)로 Fallback 하여 응답,
    // 그리고 CodeSanitizer를 타서 마크다운이 제거된 결과 반환.
    assertThat(result.getFixedCode()).isEqualTo("System.out.println(\"Fixed\");");
    assertThat(result.getExplanation()).contains("[GEMINI]");
  }
}
