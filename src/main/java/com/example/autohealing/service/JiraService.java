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
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JiraService {

  private final JiraConfig jiraConfig;
  private final WebClient webClient;

  private final Optional<HealingStrategy> healingStrategy;

  @Value("${auto-healing.mode:manual}")
  private String healingMode;

  // ─────────────────────────────────────────────────────────────────────────
  // Public API
  // ─────────────────────────────────────────────────────────────────────────

  public String createIssue(String summary, String description) {
    return createIssue(summary, description, null, null);
  }

  public String createIssue(String summary, String description, String severity, List<String> labels) {
    log.info("[Jira] 이슈 생성 시작 - mode={}, summary={}", healingMode, summary);

    Map<String, Object> payload = buildPayload(summary, description, severity, labels);
    String createdKey = callJiraApi(payload);

    if (createdKey == null) {
      log.error("[Jira] 이슈 생성 실패 - summary={}", summary);
      return null;
    }

    log.info("[Jira] 이슈 생성 성공 - key={}", createdKey);
    triggerHealingIfAuto(createdKey, summary, description);
    return createdKey;
  }

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
          .subscribeOn(Schedulers.boundedElastic())
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
   */
  public boolean addCommentToIssue(String issueKey, String comment) {
    log.info("[Jira] 이슈 댓글 추가 시도 - key={}", issueKey);

    String endpoint = jiraConfig.getHost() + "/rest/api/3/issue/" + issueKey + "/comment";
    String authHeader = buildBasicAuthHeader();

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

  /**
   * 이슈의 상태를 변경(Transition)합니다. (예: "In Progress", "Done")
   */
  @SuppressWarnings("unchecked")
  public boolean transitionIssue(String issueKey, String transitionName) {
    log.info("[Jira] 이슈 상태 전환 시도 - key={}, target={}", issueKey, transitionName);
    String endpoint = jiraConfig.getHost() + "/rest/api/3/issue/" + issueKey + "/transitions";
    String authHeader = buildBasicAuthHeader();

    try {
      Map<String, Object> transitionsResponse = webClient.get()
          .uri(endpoint)
          .header(HttpHeaders.AUTHORIZATION, authHeader)
          .retrieve()
          .bodyToMono(Map.class)
          .block();

      if (transitionsResponse == null || !transitionsResponse.containsKey("transitions")) {
        log.warn("[Jira] Transition 목록을 가져올 수 없습니다: {}", issueKey);
        return false;
      }

      List<Map<String, Object>> transitions = (List<Map<String, Object>>) transitionsResponse.get("transitions");
      String transitionId = null;
      java.util.List<String> availableNames = new java.util.ArrayList<>();

      for (Map<String, Object> tr : transitions) {
        String name = (String) tr.get("name");
        if (name != null) {
          availableNames.add(name);
          String lowerName = name.toLowerCase();
          String lowerTarget = transitionName.toLowerCase();

          if (lowerName.equals(lowerTarget) ||
              (lowerTarget.equals("in progress") && (lowerName.contains("progress") || lowerName.contains("진행"))) ||
              (lowerTarget.equals("done") && (lowerName.contains("done") || lowerName.contains("완료")))) {
            transitionId = (String) tr.get("id");
            break;
          }
        }
      }

      if (transitionId == null) {
        log.warn("[Jira] 유효한 Transition 이름을 찾을 수 없습니다: {} (target={}), available: {}", issueKey, transitionName,
            availableNames);
        return false;
      }

      Map<String, Object> payload = Map.of(
          "transition", Map.of("id", transitionId));

      webClient.post()
          .uri(endpoint)
          .header(HttpHeaders.AUTHORIZATION, authHeader)
          .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
          .bodyValue(payload)
          .retrieve()
          .toBodilessEntity()
          .block();

      log.info("[Jira] 이슈 상태 전환 성공 - key={}, to={}", issueKey, transitionName);
      return true;

    } catch (WebClientResponseException ex) {
      log.error("[Jira] 상태 전환 실패 - key={}, status={}, body={}", issueKey, ex.getStatusCode(),
          ex.getResponseBodyAsString());
      return false;
    } catch (Exception ex) {
      log.error("[Jira] 상태 전환 중 오류", ex);
      return false;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private Helpers
  // ─────────────────────────────────────────────────────────────────────────

  private Map<String, Object> buildPayload(String summary, String description, String severity, List<String> labels) {
    Map<String, Object> textNode = Map.of("type", "text", "text", description);
    Map<String, Object> paragraph = Map.of("type", "paragraph", "content", List.of(textNode));
    Map<String, Object> adfDocument = Map.of("type", "doc", "version", 1, "content", List.of(paragraph));

    String priorityName = mapSeverityToPriority(severity);

    java.util.Map<String, Object> fields = new java.util.HashMap<>(Map.of(
        "project", Map.of("key", jiraConfig.getProjectKey()),
        "summary", summary,
        "description", adfDocument,
        "issuetype", Map.of("name", "Task"),
        "priority", Map.of("name", priorityName)));

    if (labels != null && !labels.isEmpty()) {
      fields.put("labels", labels);
    }

    return Map.of("fields", fields);
  }

  private String mapSeverityToPriority(String severity) {
    if (severity == null)
      return "Medium";
    return switch (severity.toUpperCase()) {
      case "CRITICAL" -> "Highest";
      case "HIGH" -> "High";
      case "MEDIUM" -> "Medium";
      case "LOW" -> "Low";
      default -> "Medium";
    };
  }

  private Map<String, Object> buildUpdatePayload(String summary, String description) {
    Map<String, Object> textNode = Map.of("type", "text", "text", description);
    Map<String, Object> paragraph = Map.of("type", "paragraph", "content", List.of(textNode));
    Map<String, Object> adfDocument = Map.of("type", "doc", "version", 1, "content", List.of(paragraph));

    return Map.of("fields", Map.of(
        "summary", summary,
        "description", adfDocument));
  }

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
          .subscribeOn(Schedulers.boundedElastic())
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

  private String buildBasicAuthHeader() {
    String credentials = jiraConfig.getEmail() + ":" + jiraConfig.getApiToken();
    String encoded = Base64.getEncoder()
        .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    return "Basic " + encoded;
  }

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
