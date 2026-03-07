package com.example.autohealing.ai;

import com.example.autohealing.entity.PluginConfig;
import com.example.autohealing.repository.PluginConfigRepository;
import com.example.autohealing.service.EncryptionService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 시스템 내의 모든 AI 엔진(정적 + 동적)을 관리하고,
 * 장애 시 대체 엔진으로 넘어가는(Fallback) 기능을 수행하는 매니저.
 * 
 * @Primary 로 등록되어 기존 SecurityOrchestrator에 단일 구현체처럼 주입됩니다.
 */
@Slf4j
@Service
@Primary
public class AiManager implements AiRemediationService {

  private final ApplicationContext context;
  private final PluginConfigRepository pluginConfigRepository;
  private final EncryptionService encryptionService;
  private final RestTemplate restTemplate;
  private final CodeSanitizer codeSanitizer;

  public AiManager(ApplicationContext context,
      PluginConfigRepository pluginConfigRepository,
      EncryptionService encryptionService,
      RestTemplate restTemplate,
      CodeSanitizer codeSanitizer) {
    this.context = context;
    this.pluginConfigRepository = pluginConfigRepository;
    this.encryptionService = encryptionService;
    this.restTemplate = restTemplate;
    this.codeSanitizer = codeSanitizer;
  }

  @Override
  public String providerName() {
    // 단일 프로바이더 이름 대신, 체인 형태로 제공됨을 표현
    return "Multi-AI Engine (Manager)";
  }

  @Override
  public AiRemediationResult fixCode(String originalCode, String vulnerabilityInfo) {
    List<AiRemediationService> availableEngines = buildEngineChain();

    if (availableEngines.isEmpty()) {
      log.error("[AiManager] 사용 가능한 AI 엔진이 없습니다.");
      return new AiRemediationResult(originalCode, "활성화된 AI 엔진이 존재하지 않습니다.");
    }

    for (AiRemediationService engine : availableEngines) {
      log.info("[AiManager] {} 엔진으로 코드 수정 시도...", engine.providerName());
      try {
        AiRemediationResult result = engine.fixCode(originalCode, vulnerabilityInfo);

        String fixedCode = result.getFixedCode();

        // 엔진이 원본을 그대로 뱉었거나 Stub 응답이면 실패로 간주하고 다음 엔진으로 넘어감(Fallback)
        if (fixedCode != null && !fixedCode.equals(originalCode)
            && !fixedCode.contains("[AUTO-HEALING OPENAI STUB]")) {

          // 성공 시: v14 누수 방지를 위해 CodeSanitizer 실행
          String sanitized = codeSanitizer.sanitize(fixedCode);
          return new AiRemediationResult(sanitized, "[" + engine.providerName() + "] " + result.getExplanation());
        } else {
          log.warn("[AiManager] {} 엔진이 실패(또는 원본 유지). 다음 대체 수단을 찾습니다.", engine.providerName());
        }
      } catch (Exception e) {
        log.error("[AiManager] {} 엔진 처리 중 예외 발생: {}", engine.providerName(), e.getMessage());
      }
    }

    return new AiRemediationResult(originalCode, "모든 자동화 AI 엔진에서 코드 수정을 실패했습니다.");
  }

  private List<AiRemediationService> buildEngineChain() {
    List<AiRemediationService> chain = new ArrayList<>();

    // 1. DB 기반 동적 엔진 (우선순위가 가장 높음)
    List<PluginConfig> dynamicConfigs = pluginConfigRepository
        .findByPluginTypeAndEnabledTrue(PluginConfig.PluginType.AI_ENGINE);
    for (PluginConfig config : dynamicConfigs) {
      chain.add(new OpenAiCompatibleAdapter(config, restTemplate, encryptionService));
    }

    // 2. Spring Bean으로 하드코딩된 기본 엔진들 (Gemini 등)
    Map<String, AiRemediationService> staticBeans = context.getBeansOfType(AiRemediationService.class);
    for (AiRemediationService service : staticBeans.values()) {
      // 스스로를 무한 참조하는 것을 차단
      if (!(service instanceof AiManager)) {
        // OpenAI Stub은 우선순위를 가장 뒤로 미루거나, Fallback 전용으로 씀. 일단 지금은 정적 Bean은 동적 Bean 뒤에
        // 배치.
        chain.add(service);
      }
    }

    return chain;
  }
}
