package com.example.autohealing.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * GitHub 동작 및 Pull Request 생성 관련 메시지 속성을 관리합니다.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "github")
public class GithubConfig {

  private Pr pr = new Pr();

  /**
   * PR 생성 및 머지 메시지 관련 설정 (github.pr.*)
   */
  @Getter
  @Setter
  public static class Pr {
    private String titlePrefix = "[Auto-Healing]";
    private String commitPrefix = "fix: ";
    private String commitSuffix = " by AI";
    private String mergeMessage = "Merged by Auto-Healing System";
  }
}
