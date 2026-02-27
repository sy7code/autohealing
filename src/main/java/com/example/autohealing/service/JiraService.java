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
 * Jira Cloud REST API SDK를 사용하여 이슈(티켓) 생성, 수정, 상태 전환을 수행하는 통합 서비스.
 * 초기 분석 티켓 생성 및 배포 후 'Done' 처리 등 보안 О케스트레이션 라이프사이클과 연동됩니다.
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

  /**
   * 지정된 요약과 설명으로 일반적인 티켓을 생성합니다. (우선순위 및 라벨 지정 없음)
   *
   * @param summary     이슈 요약(제목)
   * @param description 이슈 상세 설명 (마크다운/해석 가능 텍스트)
   * @return 생성된 이슈 Key (예: SCRUM-123)
   */
  public String createIssue(String summary, String description) {
    return createIssue(summary, description, null, null);
  }

  /**
   * 세부 정보(위험도 및 라벨 포함)를 지정하여 Jira 이슈를 생성합니다.
   *
   * @param summary     이슈 요약(제목)
   * @param description 이슈 마크다운 상세 설명
   * @param severity    시스템 위험도 문자열 (현재는 설명용으로만 사용됨)
   * @param labels      이슈에 부여할 라벨 리스트 (미지원/추후 확장용)
   * @return 생성된 이슈 Key (예: SCRUM-123), 생성 실패 시 null 반환
   */
  public String createIssue(String summary, String description, String severity, List<String> labels) {
    if (jiraRestClient == null) {
      return null;
    }

    log.info("[Jira] 이슈 생성 시작 - mode={}, summary={}", healingMode, summary);

    try {
      Project project = jiraRestClient.getProjectClient().getProject(jiraConfig.getProjectKey()).claim();
      IssueType targetIssueType = null;
      String configuredType = jiraConfig.getIssue().getType();

      for (IssueType t : project.getIssueTypes()) {
        if (t.getName().equalsIgnoreCase(configuredType)) {
          targetIssueType = t;
          break;
        }
      }
      if (targetIssueType == null) {
        targetIssueType = project.getIssueTypes().iterator().next(); // Fallback
      }

      IssueInputBuilder builder = new IssueInputBuilder(project, targetIssueType, summary);
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

  /**
   * 이미 존재하는 이슈의 제목과 본문을 업데이트합니다.
   *
   * @param issueKey    대상 이슈 Key
   * @param summary     새로운 요약
   * @param description 새로운 설명
   * @return 수정 성공 여부
   */
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

  /**
   * 지정된 타겟 이슈에 코멘트를 추가합니다.
   * 컴파일 실패 등의 피드백 저장 용도로 사용됩니다.
   *
   * @param issueKey 대상 이슈 Key
   * @param comment  추가할 코멘트 본문
   * @return 추가 성공 여부
   */
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

  /**
   * 지정된 이슈를 'Done'(또는 설정된 완료 상태)으로 강제 전환합니다.
   *
   * @param issueKey 대상 이슈 Key
   * @return 상태 전환 성공 여부
   */
  public boolean transitionIssueToDone(String issueKey) {
    return transitionIssue(issueKey, jiraConfig.getTransition().getDone());
  }

  /**
   * 이슈의 워크플로우 상태를 주어진 전환 이름(transitionName)으로 변경합니다.
   *
   * @param issueKey       대상 이슈 Key
   * @param transitionName 목표 상태 전환 이름 (예: In Progress, Done)
   * @return 상태 전환 성공 여부
   */
  public boolean transitionIssue(String issueKey, String transitionName) {
    if (jiraRestClient == null)
      return false;
    log.info("[Jira] 이슈 상태 전환 시도 - key={}, target={}", issueKey, transitionName);

    try {
      Issue issue = jiraRestClient.getIssueClient().getIssue(issueKey).claim();
      Iterable<Transition> transitions = jiraRestClient.getIssueClient().getTransitions(issue).claim();

      Transition targetTransition = null;
      String doneStateName = jiraConfig.getTransition().getDone();

      for (Transition t : transitions) {
        String name = t.getName();
        if (name.equalsIgnoreCase(transitionName) ||
            (transitionName.equalsIgnoreCase(doneStateName)
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
