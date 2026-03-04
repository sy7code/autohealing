package com.example.autohealing.service;

/**
 * Auto-Healing 모드에서 Jira 티켓 생성 후 실행될 치료(Healing) 로직의 인터페이스.
 *
 * <p>
 * 구현체를 스프링 빈으로 등록하면 JiraService가 auto 모드일 때 자동으로 호출합니다.
 * 예) SnykHealingStrategy, AzureHealingStrategy 등을 별도로 구현하여 주입하세요.
 */
public interface HealingStrategy {

  /**
   * 감지된 위협에 대해 자동 치료 로직을 수행합니다.
   *
   * @param issueKey    생성된 Jira 이슈 키 (예: "SCRUM-42")
   * @param summary     위협 요약 문자열
   * @param description 위협 상세 설명
   */
  void heal(String issueKey, String summary, String description);
}
