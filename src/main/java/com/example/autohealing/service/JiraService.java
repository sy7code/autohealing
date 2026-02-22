package com.example.autohealing.service;

import com.example.autohealing.config.JiraConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Jira Cloud REST API v3를 통해 이슈를 생성/수정하는 서비스.
 *
 * <h3>인증</h3>
 * Basic Auth: Base64(email:apiToken) 을 Authorization 헤더에 설정합니다.
 *
 * <h3>주요 메서드</h3>
 * <ul>
 * <li>{@link #createIssue} : POST /rest/api/3/issue 로 새 티켓 생성</li>
 * <li>{@link #updateIssue} : PUT /rest/api/3/issue/{key} 로 기존 티켓 수정</li>
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JiraService {

  private final JiraConfig jiraConfig;
  private final WebClient webClient;

  /**
   * 선택적(Optional) 주입: auto 모드에서만 필요합니다.
   * 구현체가 없으면 빈 Optional이 주입됩니다.
   */
  private final Optional<HealingStrategy> healingStrategy;

  /**
   * auto-healing.mode 설정 값 ("auto" | "manual").
   * 기본값은 "manual" 입니다.
   */
  @Value("${auto-healing.mode:manual}")
  private String healingMode;

  // ─────────────────────────────────────────────────────────────────────────
  // Public API
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Jira 이슈를 생성합니다.
   *
   * @param summary     이슈 제목 (1줄 요약)
   * @param description 이슈 상세 설명 (ADF 본문에 삽입)
   * @return 생성된 이슈의 key (예: "SCRUM-42"), 실패 시 null
   */
  public String createIssue(String summary, String description) {
    log.info("[Jira] 이슈 생성 시작 - mode={}, summary={}", healingMode, summary);

    Map<String, Object> payload = buildPayload(summary, description);
    String createdKey = callJiraApi(payload);

    if (createdKey == null) {
      log.error("[Jira] 이슈 생성 실패 - summary={}", summary);
      return null;
    }

    log.info("[Jira] 이슈 생성 성공 - key={}", createdKey);
    triggerHealingIfAuto(createdKey, summary, description);
    return createdKey;
  }

  /**
   * 기존 Jira 이슈의 Summary와 Description을 수정합니다.
   *
   * <p>
   * SecurityOrchestrator의 2단계에서 "분석 중" 티켓을 실제 결과로 교체할 때 사용합니다.
   *
   * @param issueKey    수정할 이슈 키 (예: "SCRUM-42")
   * @param summary     새 Summary 텍스트
   * @param description 새 Description 텍스트 (ADF 포맷으로 변환됨)
   * @return 수정 성공 시 {@code true}, 실패 시 {@code false}
   */
  public boolean updateIssue(String issueKey, String summary, String description) {
    log.info("[Jira] 이슈 수정 시작 - key={}, summary={}", issueKey, summary);

    String endpoint = jiraConfig.getHost() + "/rest/api/3/issue/" + issueKey;
    String authHeader = buildBasicAuthHeader();
    Map<String, Object> payload = buildUpdatePayload(summary, description);

    try {
      webClient.put()
          .uri(endpoint)
          .header(HttpHeaders.AUTHORIZATION, authHeader)
          .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
          .bodyValue(payload)
          .retrieve()
          .toBodilessEntity()
          .subscribeOn(Schedulers.boundedElastic()) // nio 스레드 외부에서 block() 실행
          .block();

      log.info("[Jira] 이슈 수정 성공 - key={}", issueKey);
      return true;

    } catch (WebClientResponseException ex) {
      log.error("[Jira] 이슈 수정 실패 - key={}, status={}, body={}",
          issueKey, ex.getStatusCode(), ex.getResponseBodyAsString());
      return false;
    } catch (Exception ex) {
      log.error("[Jira] 이슈 수정 중 예기치 못한 오류 - key={}", issueKey, ex);
      return false;
    }
  }

  /**
   * 이슈에 댓글을 추가합니다.
   *
   * @param issueKey 등록할 이슈 키 (예: "SCRUM-42")
   * @param comment  등록할 댓글 본문 (ADF 포맷으로 변환됨)
   * @return 성공 여부
   */
  public boolean addCommentToIssue(String issueKey, String comment) {
    log.info("[Jira] 이슈 댓글 추가 시도 - key={}", issueKey);

    String endpoint = jiraConfig.getHost() + "/rest/api/3/issue/" + issueKey + "/comment";
    String authHeader = buildBasicAuthHeader();

    // ADF 포맷 (type: doc) 구성
    Map<String, Object> textNode = Map.of("type", "text", "text", comment);
    Map<String, Object> paragraph = Map.of("type", "paragraph", "content", List.of(textNode));
    Map<String, Object> adfDocument = Map.of("type", "doc", "version", 1, "content", List.of(paragraph));

    Map<String, Object> payload = Map.of("body", adfDocument);

    try {
      webClient.post()
          .uri(endpoint)
          .header(HttpHeaders.AUTHORIZATION, authHeader)
          .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
          .bodyValue(payload)
          .retrieve()
          .toBodilessEntity()
          .subscribeOn(Schedulers.boundedElastic())
          .block();

      log.info("[Jira] 이슈 댓글 추가 성공 - key={}", issueKey);
      return true;

    } catch (WebClientResponseException ex) {
      log.error("[Jira] 이슈 댓글 추가 실패 - key={}, status={}, body={}",
          issueKey, ex.getStatusCode(), ex.getResponseBodyAsString());
      return false;
    } catch (Exception ex) {
      log.error("[Jira] 이슈 댓글 추가 중 예기치 못한 오류 - key={}", issueKey, ex);
      return false;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private Helpers
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Jira API 요청 바디(payload)를 조립합니다.
   * Description은 Atlassian Document Format (ADF)을 사용합니다.
   */
  private Map<String, Object> buildPayload(String summary, String description) {
    // ADF: doc > paragraph > text
    Map<String, Object> textNode = Map.of(
        "type", "text",
        "text", description);
    Map<String, Object> paragraph = Map.of(
        "type", "paragraph",
        "content", List.of(textNode));
    Map<String, Object> adfDocument = Map.of(
        "type", "doc",
        "version", 1,
        "content", List.of(paragraph));

    return Map.of(
        "fields", Map.of(
            "project", Map.of("key", jiraConfig.getProjectKey()),
            "summary", summary,
            "description", adfDocument,
            "issuetype", Map.of("name", "Task")));
  }

  /**
   * 이슈 수정(PUT)용 payload. issuetype 없이 summary + description만 포함합니다.
   */
  private Map<String, Object> buildUpdatePayload(String summary, String description) {
    Map<String, Object> textNode = Map.of("type", "text", "text", description);
    Map<String, Object> paragraph = Map.of("type", "paragraph", "content", List.of(textNode));
    Map<String, Object> adfDocument = Map.of("type", "doc", "version", 1, "content", List.of(paragraph));

    return Map.of("fields", Map.of(
        "summary", summary,
        "description", adfDocument));
  }

  /**
   * Jira REST API를 실제로 호출합니다.
   *
   * @return 생성된 이슈 key, 오류 발생 시 null
   */
  @SuppressWarnings("unchecked")
  private String callJiraApi(Map<String, Object> payload) {
    String endpoint = jiraConfig.getHost() + "/rest/api/3/issue";
    String authHeader = buildBasicAuthHeader();

    try {
      Map<String, Object> response = webClient.post()
          .uri(endpoint)
          .header(HttpHeaders.AUTHORIZATION, authHeader)
          .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
          .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
          .bodyValue(payload)
          .retrieve()
          .bodyToMono(Map.class)
          .subscribeOn(Schedulers.boundedElastic()) // nio 스레드 외부에서 block() 실행
          .block();

      if (response != null && response.containsKey("key")) {
        return (String) response.get("key");
      }
      log.warn("[Jira] 응답에 'key' 필드가 없습니다. response={}", response);
      return null;

    } catch (WebClientResponseException ex) {
      log.error("[Jira] API 오류 - status={}, body={}", ex.getStatusCode(), ex.getResponseBodyAsString());
      return null;
    } catch (Exception ex) {
      log.error("[Jira] 예기치 못한 오류 발생", ex);
      return null;
    }
  }

  /**
   * "Basic Base64(email:apiToken)" 형식의 Authorization 헤더 값을 생성합니다.
   */
  private String buildBasicAuthHeader() {
    String credentials = jiraConfig.getEmail() + ":" + jiraConfig.getApiToken();
    String encoded = Base64.getEncoder()
        .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    return "Basic " + encoded;
  }

  /**
   * auto 모드인 경우 HealingStrategy를 호출합니다.
   * manual 모드이거나 구현체가 없으면 아무 것도 하지 않습니다.
   */
  private void triggerHealingIfAuto(String issueKey, String summary, String description) {
    if (!"auto".equalsIgnoreCase(healingMode)) {
      log.info("[Jira] manual 모드 - Healing 로직을 건너뜁니다. key={}", issueKey);
      return;
    }

    if (healingStrategy.isEmpty()) {
      log.warn("[Jira] auto 모드이지만 HealingStrategy 구현체가 없습니다. key={}", issueKey);
      return;
    }

    log.info("[Jira] auto 모드 - Healing 로직 실행. key={}", issueKey);
    healingStrategy.get().heal(issueKey, summary, description);
  }
}
