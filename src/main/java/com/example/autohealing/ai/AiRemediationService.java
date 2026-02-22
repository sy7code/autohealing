package com.example.autohealing.ai;

import java.util.List;

/**
 * AI 코드 수정 엔진 인터페이스.
 *
 * <p>
 * 구현체를 교체하면 Gemini, OpenAI, Anthropic 등 어떤 AI 모델로도 전환할 수 있습니다.
 * {@link com.example.autohealing.config.AiServiceConfig}에서 {@code ai.type} 속성으로
 * 주입할 구현체를 결정합니다.
 *
 * <h3>흐름</h3>
 * 
 * <pre>
 * SecurityOrchestrator
 *   → AiRemediationService.fixCode(originalCode, vulnInfo)
 *   → [Gemini/OpenAI API 호출]
 *   → 수정된 소스 코드 반환
 * </pre>
 */
public interface AiRemediationService {

  /**
   * 취약점을 포함한 원본 소스 코드를 AI에게 전달하여 수정된 코드를 반환받습니다.
   *
   * @param originalCode      취약점이 발견된 원본 소스 코드 (전체 파일 내용)
   * @param vulnerabilityInfo 취약점 설명 (ID, 제목, 심각도 등 요약 문자열)
   * @return 수정된 결과 (수정된 전체 코드와 한글 설명 포함). AI 호출 실패 시 코드를 원본으로 반환.
   */
  AiRemediationResult fixCode(String originalCode, String vulnerabilityInfo);

  /**
   * 이 구현체가 사용하는 AI 제공자 이름.
   * 로그 및 설정 확인에 사용됩니다.
   *
   * @return 예: "GEMINI", "OPENAI"
   */
  String providerName();

  /**
   * 지원하는 AI 제공자 목록.
   * 새 구현체를 추가할 때 이 목록도 업데이트하세요.
   */
  List<String> SUPPORTED_PROVIDERS = List.of("GEMINI", "OPENAI");
}
