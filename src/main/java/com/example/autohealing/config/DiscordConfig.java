package com.example.autohealing.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Discord notification configuration properties.
 * Binds properties prefixed with 'discord' from application.yml.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "discord")
public class DiscordConfig {

  /**
   * The Discord Webhook URL to send notifications to.
   */
  private String webhookUrl;
}
