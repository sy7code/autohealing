package com.example.autohealing.parser;

import com.example.autohealing.parser.dto.UnifiedIssue;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 등록된 {@link IssueParser} 구현체를 도구명으로 조회하고 실행하는 파서 레지스트리.
 *
 * <p>
 * 스프링이 {@code IssueParser} 구현체 목록을 자동으로 주입하므로,
 * 새 파서를 {@code @Component}로 등록하면 코드 변경 없이 자동으로 사용 가능합니다.
 *
 * <h3>사용 예시</h3>
 * 
 * <pre>
 * {@code
 * List<UnifiedIssue> issues = issueManager.parse("SNYK", snykRawJson);
 * }
 * </pre>
 */
@Slf4j
@Service
public class IssueManager {

  /**
   * 도구명(toolName) → IssueParser 매핑 테이블.
   * 스프링 컨텍스트의 모든 IssueParser 빈을 자동으로 수집합니다.
   */
  private final Map<String, IssueParser<Object>> parserRegistry;

  /**
   * @param parsers 스프링이 주입하는 IssueParser 구현체 목록
   */
  @SuppressWarnings("unchecked")
  public IssueManager(List<IssueParser<?>> parsers) {
    this.parserRegistry = parsers.stream()
        .collect(Collectors.toMap(
            p -> p.toolName().toUpperCase(),
            p -> (IssueParser<Object>) p));
    log.info("[IssueManager] 등록된 파서: {}", parserRegistry.keySet());
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public API
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * 지정한 도구의 파서를 찾아 원본 데이터를 파싱합니다.
   *
   * @param toolName 파서를 조회할 도구명 (대소문자 무관, 예: "snyk", "SNYK")
   * @param rawData  파서에 전달할 원본 데이터
   * @return 표준화된 {@link UnifiedIssue} 목록 (파서 없거나 오류 시 빈 리스트)
   */
  public List<UnifiedIssue> parse(String toolName, Object rawData) {
    if (toolName == null || toolName.isBlank()) {
      log.warn("[IssueManager] 도구명이 null 또는 빈 값입니다.");
      return List.of();
    }

    IssueParser<Object> parser = parserRegistry.get(toolName.toUpperCase());

    if (parser == null) {
      log.warn("[IssueManager] '{}' 에 해당하는 파서를 찾을 수 없습니다. 등록된 파서: {}",
          toolName, parserRegistry.keySet());
      return List.of();
    }

    try {
      log.info("[IssueManager] '{}' 파서 실행 시작.", toolName.toUpperCase());
      List<UnifiedIssue> issues = parser.parse(rawData);
      log.info("[IssueManager] '{}' 파서 완료 - 변환된 이슈 수: {}",
          toolName.toUpperCase(), issues.size());
      return issues;
    } catch (Exception e) {
      log.error("[IssueManager] '{}' 파서 실행 중 오류 발생.", toolName, e);
      return List.of();
    }
  }

  /**
   * 현재 등록된 모든 파서의 도구명 목록을 반환합니다.
   *
   * @return 도구명 집합 (예: ["SNYK", "AZURE"])
   */
  public java.util.Set<String> registeredTools() {
    return parserRegistry.keySet();
  }
}
