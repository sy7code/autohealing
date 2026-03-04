package com.example.autohealing.parser;

import com.example.autohealing.parser.dto.UnifiedIssue;

import java.util.List;

/**
 * 보안 도구의 원본 데이터를 {@link UnifiedIssue} 목록으로 변환하는 파서 인터페이스.
 *
 * <p>
 * 각 보안 도구(Snyk, Azure, 커스텀 등)는 이 인터페이스를 구현하여
 * 도구별 원본 JSON/XML/객체 데이터를 공통 형식으로 변환합니다.
 *
 * <h3>구현 예시</h3>
 * 
 * <pre>
 * {
 *   &#64;code
 *   &#64;Component
 *   public class SnykParserImpl implements IssueParser {
 *     &#64;Override
 *     public String toolName() {
 *       return "SNYK";
 *     }
 *
 *     @Override
 *     public List<UnifiedIssue> parse(String rawData) {
 *       // Snyk JSON 파싱 로직
 *     }
 *   }
 * }
 * </pre>
 *
 * @param <T> 파서가 처리하는 원본 데이터 타입 (String JSON, Map, 커스텀 객체 등)
 */
public interface IssueParser<T> {

  /**
   * 이 파서가 처리하는 도구의 이름을 반환합니다.
   * {@link com.example.autohealing.parser.IssueManager}가 파서를 조회할 때 사용합니다.
   *
   * @return 도구명 (대문자 권장, 예: "SNYK", "AZURE", "CUSTOM")
   */
  String toolName();

  /**
   * 보안 도구의 원본 데이터를 표준화된 {@link UnifiedIssue} 목록으로 변환합니다.
   *
   * @param rawData 도구별 원본 데이터
   * @return 변환된 {@link UnifiedIssue} 목록 (이슈가 없으면 빈 리스트)
   */
  List<UnifiedIssue> parse(T rawData);
}
