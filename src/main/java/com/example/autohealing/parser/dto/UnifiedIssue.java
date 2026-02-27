package com.example.autohealing.parser.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

/**
 * 모든 보안 도구의 이슈 데이터를 표준화한 통합 DTO.
 *
 * <p>
 * 다양한 소스(Snyk, Azure Security, 커스텀 툴 등)의 원본 데이터를
 * Jira 티켓 생성에 필요한 최소한의 공통 정보로 정규화합니다.
 *
 * <pre>
 * 필드 설명:
 *  - id         : 소스 도구 내의 고유 식별자 (중복 티켓 방지에 사용)
 *  - source     : 이슈 출처 도구명 (예: "SNYK", "AZURE", "CUSTOM")
 *  - title      : Jira Summary에 사용될 한 줄 제목
 *  - description: Jira Description(ADF 본문)에 사용될 상세 설명
 *  - severity   : 표준화된 위험도 등급 (SeverityLevel 열거형)
 * </pre>
 */
@Getter
@Builder
@ToString
public class UnifiedIssue {

  /** 소스 도구 내부의 고유 이슈 ID */
  private final String id;

  /** 이슈를 발생시킨 도구명 (예: "SNYK", "AZURE") */
  private final String source;

  /** Jira 티켓 Summary로 사용될 제목 */
  private final String title;

  /** Jira 티켓 Description으로 사용될 상세 내용 */
  @lombok.Setter
  private String description;

  /** 표준화된 위험도 등급 */
  private final SeverityLevel severity;

  // ─────────────────────────────────────────────────────────
  // 위험도 등급 정의
  // ─────────────────────────────────────────────────────────

  /**
   * 표준화된 위험도 등급.
   * 소스 도구에서 제공하는 등급 문자열을 이 enum으로 통일합니다.
   */
  public enum SeverityLevel {
    /** 즉시 대응 필요 */
    CRITICAL,
    /** 높은 위험 */
    HIGH,
    /** 중간 위험 (기본값) */
    MEDIUM,
    /** 낮은 위험 */
    LOW,
    /** 정보성 */
    INFO
  }
}
