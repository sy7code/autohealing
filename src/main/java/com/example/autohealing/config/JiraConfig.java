package com.example.autohealing.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Jira 연동에 필요한 설정 빈을 등록합니다.
 *
 * application.yml 의 jira.* 프로퍼티를 자동으로 바인딩하며,
 * HTTP 클라이언트로 RestTemplate과 WebClient 두 가지를 모두 제공합니다.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "jira")
public class JiraConfig {

  /** Jira Cloud 호스트 URL (예: https://your-domain.atlassian.net) */
  private String host;

  /** Jira 계정 이메일 */
  private String email;

  /** Jira API Token */
  private String apiToken;

  /** Jira 프로젝트 키 (예: SCRUM) */
  private String projectKey;

  private Transition transition = new Transition();
  private Issue issue = new Issue();

  /**
   * 워크플로우 상태 전이 관련 설정 (jira.transition.*)
   */
  @Getter
  @Setter
  public static class Transition {
    private String inProgress = "In Progress";
    private String done = "Done";
  }

  /**
   * 기본 이슈 유형 관련 설정 (jira.issue.*)
   */
  @Getter
  @Setter
  public static class Issue {
    private String type = "Task";
  }

  // ───────────────────────────────────────────────────────────────────────────
  // HTTP 클라이언트 빈
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * 동기식 HTTP 클라이언트.
   * spring-boot-starter-web 이 없는 WebFlux 환경에서도 수동으로 등록합니다.
   */
  @Bean
  public RestTemplate restTemplate() {
    return new RestTemplate();
  }

  /**
   * 비동기식 HTTP 클라이언트.
   * WebFlux 스택이 이미 포함되어 있으므로 기본 WebClient를 빈으로 등록합니다.
   */
  @Bean
  public WebClient webClient() {
    return WebClient.builder().build();
  }
}
