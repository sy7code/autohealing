package com.example.autohealing.parser.snyk;

import com.example.autohealing.parser.IssueParser;
import com.example.autohealing.parser.SeverityMapper;
import com.example.autohealing.parser.dto.UnifiedIssue;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Snyk 취약점 데이터를 {@link UnifiedIssue}로 변환하는 파서 구현체.
 *
 * <p>
 * Snyk REST API / CLI 결과를 파싱하여 Jira 티켓 생성에 필요한
 * 정보를 표준화합니다.
 *
 * <h3>지원하는 Snyk 데이터 구조 (Map 기반)</h3>
 * 
 * <pre>
 * {
 *   "vulnerabilities": [
 *     {
 *       "id":          "SNYK-JAVA-XXX-12345",
 *       "title":       "Remote Code Execution",
 *       "description": "A critical vulnerability in ...",
 *       "severity":    "high",
 *       "packageName": "log4j",
 *       "version":     "2.14.1"
 *     }
 *   ]
 * }
 * </pre>
 *
 * <p>
 * 데이터를 JSON 문자열로 수신하는 경우 ObjectMapper로 Map 변환 후 사용하세요.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SnykParserImpl implements IssueParser<Map<String, Object>> {

  private final SeverityMapper severityMapper;

  /** IssueManager 레지스트리 조회 키 */
  @Override
  public String toolName() {
    return "SNYK";
  }

  /**
   * Snyk 원본 데이터 Map을 {@link UnifiedIssue} 목록으로 변환합니다.
   *
   * @param rawData Snyk 결과 Map (최상위에 "vulnerabilities" 리스트 포함)
   * @return 변환된 {@link UnifiedIssue} 목록
   */
  @Override
  @SuppressWarnings("unchecked")
  public List<UnifiedIssue> parse(Map<String, Object> rawData) {
    List<UnifiedIssue> result = new ArrayList<>();

    if (rawData == null || !rawData.containsKey("vulnerabilities")) {
      log.warn("[SnykParser] 'vulnerabilities' 키가 없습니다. 빈 목록을 반환합니다.");
      return result;
    }

    List<Map<String, Object>> vulnerabilities = (List<Map<String, Object>>) rawData.get("vulnerabilities");

    for (Map<String, Object> vuln : vulnerabilities) {
      try {
        result.add(toUnifiedIssue(vuln));
      } catch (Exception e) {
        log.warn("[SnykParser] 이슈 변환 중 오류 - 건너뜁니다. vuln={}", vuln, e);
      }
    }

    log.info("[SnykParser] 파싱 완료 - 총 {}건 / 성공 {}건",
        vulnerabilities.size(), result.size());
    return result;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private Helpers
  // ─────────────────────────────────────────────────────────────────────────

  private UnifiedIssue toUnifiedIssue(Map<String, Object> vuln) {
    String id = getString(vuln, "id", "SNYK-UNKNOWN");
    String title = getString(vuln, "title", "제목 없음");
    String description = getString(vuln, "description", "");
    String rawSeverity = getString(vuln, "severity", null);
    String packageName = getString(vuln, "packageName", "unknown");
    String version = getString(vuln, "version", "unknown");

    // 등급 표준화 (직접 매핑 → 키워드 추론 → 기본값 MEDIUM)
    UnifiedIssue.SeverityLevel severity = severityMapper.map(rawSeverity, title + " " + description);

    // Jira 티켓 Summary 포맷
    String jiraTitle = String.format("[Snyk][%s] %s (%s@%s)",
        severity.name(), title, packageName, version);

    // Jira 티켓 Description 포맷
    String jiraDescription = buildDescription(id, title, description, packageName, version, rawSeverity, severity);

    return UnifiedIssue.builder()
        .id(id)
        .source("SNYK")
        .title(jiraTitle)
        .description(jiraDescription)
        .severity(severity)
        .build();
  }

  private String buildDescription(String id, String title, String description,
      String packageName, String version,
      String rawSeverity, UnifiedIssue.SeverityLevel severity) {
    return String.format("""
        🔐 Snyk 취약점 감지 보고서
        ──────────────────────────────
        ID          : %s
        제목        : %s
        패키지      : %s @ %s
        원본 등급   : %s
        표준화 등급 : %s
        ──────────────────────────────
        상세 설명:
        %s
        """,
        id, title, packageName, version,
        rawSeverity != null ? rawSeverity : "(없음)",
        severity.name(),
        description);
  }

  private String getString(Map<String, Object> map, String key, String defaultValue) {
    Object value = map.get(key);
    return (value instanceof String s && !s.isBlank()) ? s : defaultValue;
  }
}
