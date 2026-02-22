package com.example.autohealing.parser;

import com.example.autohealing.parser.dto.UnifiedIssue.SeverityLevel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * 보안 도구의 등급 문자열을 {@link SeverityLevel}로 표준화하는 유틸리티.
 *
 * <h3>동작 방식</h3>
 * <ol>
 * <li>도구가 제공한 등급 문자열을 직접 매핑 (예: "HIGH" → HIGH)</li>
 * <li>매핑 실패 시 설명 텍스트에서 키워드를 탐지하여 등급 추론</li>
 * <li>키워드도 없으면 기본값 {@code MEDIUM} 부여</li>
 * </ol>
 */
@Slf4j
@Component
public class SeverityMapper {

  /** 기본 등급: 소스 도구에서 등급 정보를 제공하지 않을 때 사용 */
  private static final SeverityLevel DEFAULT_SEVERITY = SeverityLevel.MEDIUM;

  /**
   * 도구별 등급 문자열 → SeverityLevel 직접 매핑 테이블.
   * 대소문자를 통일하여 관리합니다.
   */
  private static final Map<String, SeverityLevel> STRING_MAP = Map.of(
      "critical", SeverityLevel.CRITICAL,
      "high", SeverityLevel.HIGH,
      "medium", SeverityLevel.MEDIUM,
      "moderate", SeverityLevel.MEDIUM, // npm audit 등 사용
      "low", SeverityLevel.LOW,
      "info", SeverityLevel.INFO,
      "informational", SeverityLevel.INFO);

  /**
   * 텍스트 키워드 → SeverityLevel 추론 테이블.
   * 도구가 등급 수치를 제공하지 않을 때 문장 분석에 사용됩니다.
   * 우선순위: CRITICAL > HIGH > LOW > INFO (기본값 MEDIUM)
   */
  private static final Map<String, SeverityLevel> KEYWORD_MAP = Map.of(
      "exploit", SeverityLevel.CRITICAL,
      "remote code", SeverityLevel.CRITICAL,
      "rce", SeverityLevel.CRITICAL,
      "critical", SeverityLevel.CRITICAL,
      "injection", SeverityLevel.HIGH,
      "privilege", SeverityLevel.HIGH,
      "xss", SeverityLevel.HIGH,
      "low", SeverityLevel.LOW,
      "info", SeverityLevel.INFO);

  // ─────────────────────────────────────────────────────────────────────────
  // Public API
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * 도구 제공 등급 문자열을 이용해 {@link SeverityLevel}로 변환합니다.
   * 변환에 실패하면 {@code descriptionText}에서 키워드를 분석합니다.
   *
   * @param rawSeverity     도구가 제공한 원시 등급 문자열 (null 또는 빈 문자열 허용)
   * @param descriptionText 키워드 분석에 사용할 이슈 설명 텍스트
   * @return 표준화된 {@link SeverityLevel}
   */
  public SeverityLevel map(String rawSeverity, String descriptionText) {
    // 1단계: 직접 매핑 시도
    SeverityLevel mapped = mapFromString(rawSeverity);
    if (mapped != null) {
      return mapped;
    }

    // 2단계: 설명 텍스트 키워드 분석
    SeverityLevel inferred = inferFromText(descriptionText);
    if (inferred != null) {
      log.debug("[SeverityMapper] 등급 직접 매핑 실패, 키워드로 추론: rawSeverity='{}' → {}",
          rawSeverity, inferred);
      return inferred;
    }

    // 3단계: 기본값 부여
    log.debug("[SeverityMapper] 등급 추론 불가, 기본값 부여: rawSeverity='{}' → {}",
        rawSeverity, DEFAULT_SEVERITY);
    return DEFAULT_SEVERITY;
  }

  /**
   * 등급 문자열 없이, 텍스트 분석만으로 등급을 결정합니다.
   * 등급 정보를 아예 제공하지 않는 커스텀 툴에 사용할 수 있습니다.
   *
   * @param descriptionText 분석할 텍스트
   * @return 표준화된 {@link SeverityLevel} (추론 불가 시 기본값 MEDIUM)
   */
  public SeverityLevel mapFromTextOnly(String descriptionText) {
    return map(null, descriptionText);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private Helpers
  // ─────────────────────────────────────────────────────────────────────────

  private SeverityLevel mapFromString(String rawSeverity) {
    if (rawSeverity == null || rawSeverity.isBlank()) {
      return null;
    }
    return STRING_MAP.get(rawSeverity.trim().toLowerCase());
  }

  private SeverityLevel inferFromText(String text) {
    if (text == null || text.isBlank()) {
      return null;
    }
    String lowerText = text.toLowerCase();

    // CRITICAL 키워드 우선 탐지
    for (Map.Entry<String, SeverityLevel> entry : KEYWORD_MAP.entrySet()) {
      if (entry.getValue() == SeverityLevel.CRITICAL && lowerText.contains(entry.getKey())) {
        return SeverityLevel.CRITICAL;
      }
    }
    // 나머지 키워드 탐지
    for (Map.Entry<String, SeverityLevel> entry : KEYWORD_MAP.entrySet()) {
      if (lowerText.contains(entry.getKey())) {
        return entry.getValue();
      }
    }
    return null;
  }
}
