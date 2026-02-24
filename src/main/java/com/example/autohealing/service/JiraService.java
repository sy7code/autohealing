package com.example.autohealing.service;

import com.atlassian.jira.rest.client.api.JiraRestClient;
import com.atlassian.jira.rest.client.api.domain.BasicIssue;
import com.atlassian.jira.rest.client.api.domain.Issue;
import com.atlassian.jira.rest.client.api.domain.IssueType;
import com.atlassian.jira.rest.client.api.domain.Project;
import com.atlassian.jira.rest.client.api.domain.Transition;
import com.atlassian.jira.rest.client.api.domain.input.IssueInput;
import com.atlassian.jira.rest.client.api.domain.input.IssueInputBuilder;
import com.atlassian.jira.rest.client.api.domain.input.TransitionInput;
import com.atlassian.jira.rest.client.internal.async.AsynchronousJiraRestClientFactory;
import com.example.autohealing.config.JiraConfig;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.List;
import java.util.Optional;

/**
 * Jira Cloud REST API SDK를 통해 이슈를 생성/수정하는 서비스.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JiraService {

  private final JiraConfig jiraConfig;
  private final Optional<HealingStrategy> healingStrategy;

  private JiraRestClient jiraRestClient;

  @Value("${auto-healing.mode:manual}")
  private String healingMode;

  @PostConstruct
  public void init() {
    try {
      this.jiraRestClient = new AsynchronousJiraRestClientFactory()
          .createWithBasicHttpAuthentication(
              URI.create(jiraConfig.getHost()),
              jiraConfig.getEmail(),
              jiraConfig.getApiToken());
      log.info("[Jira] Jira SDK Client 초기화 완료");
    } catch (Exception e) {
      log.error("[Jira] Jira SDK Client 초기화 에러", e);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public API
  // ─────────────────────────────────────────────────────────────────────────

  public String createIssue(String summary, String description) {
    return createIssue(summary, description, null, null);
  }

  public String createIssue(String summary, String description, String severity, List<String> labels) {
    if (jiraRestClient == null)
      return null;

    log.info("[Jira] 이슈 생성 시작 - mode={}, summary={}", healingMode, summary);

    try {
      Project project = jiraRestClient.getProjectClient().getProject(jiraConfig.getProjectKey()).claim();
      IssueType taskType = null;
      for (IssueType t : project.getIssueTypes()) {
        if (t.getName().equalsIgnoreCase("Task")) {
          taskType = t;
          break;
        }
      }
      if (taskType == null) {
        taskType = project.getIssueTypes().iterator().next(); // Fallback
      }

      IssueInputBuilder builder = new IssueInputBuilder(project, taskType, summary);
      builder.setDescription(description);

      // Note: Atlassian SDK does not provide a robust way to add string labels
      // directly
      // without looking up Field ID mappings. We're skipping labels for now.

      IssueInput input = builder.build();
      BasicIssue basicIssue = jiraRestClient.getIssueClient().createIssue(input).claim();

      log.info("[Jira] 이슈 생성 성공 - key={}", basicIssue.getKey());
      triggerHealingIfAuto(basicIssue.getKey(), summary, description);

      return basicIssue.getKey();

    } catch (Exception e) {
      log.error("[Jira] 이슈 생성 실패 - summary={}", summary, e);
      return null;
    }
  }

  public boolean updateIssue(String issueKey, String summary, String description) {
    if (jiraRestClient == null)
      return false;
    log.info("[Jira] 이슈 수정 시작 - key={}, summary={}", issueKey, summary);

    try {
      IssueInputBuilder builder = new IssueInputBuilder();
      builder.setSummary(summary);
      builder.setDescription(description);

      jiraRestClient.getIssueClient().updateIssue(issueKey, builder.build()).claim();
      log.info("[Jira] 이슈 수정 성공 - key={}", issueKey);
      return true;
    } catch (Exception e) {
      log.error("[Jira] 이슈 수정 중 예기치 못한 오류 - key={}", issueKey, e);
      return false;
    }
  }

  public boolean addCommentToIssue(String issueKey, String comment) {
    if (jiraRestClient == null)
      return false;
    log.info("[Jira] 이슈 댓글 추가 시도 - key={}", issueKey);

    try {
      Issue issue = jiraRestClient.getIssueClient().getIssue(issueKey).claim();
      jiraRestClient.getIssueClient()
          .addComment(issue.getCommentsUri(), com.atlassian.jira.rest.client.api.domain.Comment.valueOf(comment))
          .claim();
      log.info("[Jira] 이슈 댓글 추가 성공 - key={}", issueKey);
      return true;
    } catch (Exception e) {
      log.error("[Jira] 이슈 댓글 추가 중 오류 발생 - key={}", issueKey, e);
      return false;
    }
  }

  public boolean transitionIssueToDone(String issueKey) {
    return transitionIssue(issueKey, "Done");
  }

  public boolean transitionIssue(String issueKey, String transitionName) {
    if (jiraRestClient == null)
      return false;
    log.info("[Jira] 이슈 상태 전환 시도 - key={}, target={}", issueKey, transitionName);

    try {
      Issue issue = jiraRestClient.getIssueClient().getIssue(issueKey).claim();
      Iterable<Transition> transitions = jiraRestClient.getIssueClient().getTransitions(issue).claim();

      Transition targetTransition = null;
      for (Transition t : transitions) {
        String name = t.getName();
        if (name.equalsIgnoreCase(transitionName) ||
            (transitionName.equalsIgnoreCase("Done")
                && (name.toLowerCase().contains("done") || name.toLowerCase().contains("완료")))) {
          targetTransition = t;
          break;
        }
      }

      if (targetTransition == null) {
        log.warn("[Jira] 유효한 Transition 이름을 찾을 수 없습니다: {} (target={})", issueKey, transitionName);
        return false;
      }

      TransitionInput transitionInput = new TransitionInput(targetTransition.getId());
      jiraRestClient.getIssueClient().transition(issue, transitionInput).claim();

      log.info("[Jira] 이슈 상태 전환 성공 - key={}, to={}", issueKey, transitionName);
      return true;
    } catch (Exception e) {
      log.error("[Jira] 상태 전환 중 오류", e);
      return false;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private Helpers
  // ─────────────────────────────────────────────────────────────────────────

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
