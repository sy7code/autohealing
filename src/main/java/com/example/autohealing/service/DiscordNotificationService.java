package com.example.autohealing.service;

import com.example.autohealing.config.DiscordConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Service for sending real-time notifications to a Discord Webhook.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DiscordNotificationService {

  private final DiscordConfig discordConfig;
  private final RestTemplate restTemplate;

  // Discord Embed Colors (Decimal format)
  private static final int COLOR_RED = 16711680; // High severity / Errors
  private static final int COLOR_YELLOW = 16776960; // Warnings / Pending
  private static final int COLOR_GREEN = 65280; // Success / Info

  /**
   * Sends a generic alert to Discord using embeds.
   *
   * @param title       The embed title.
   * @param description The embed description.
   * @param color       The decimal color code.
   */
  public void sendEmbedAlert(String title, String description, int color) {
    if (discordConfig.getWebhookUrl() == null || discordConfig.getWebhookUrl().isBlank()) {
      log.warn("Discord Webhook URL is not configured. Skipping notification.");
      return;
    }

    try {
      Map<String, Object> embed = new HashMap<>();
      embed.put("title", title);
      embed.put("description", description);
      embed.put("color", color);

      Map<String, Object> payload = new HashMap<>();
      payload.put("embeds", Collections.singletonList(embed));

      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      HttpEntity<Map<String, Object>> request = new HttpEntity<>(payload, headers);

      restTemplate.postForEntity(discordConfig.getWebhookUrl(), request, String.class);
      log.info("Successfully sent Discord notification: {}", title);
    } catch (Exception e) {
      log.error("Failed to send Discord notification", e);
    }
  }

  /**
   * Sends a notification when a Snyk vulnerability is detected.
   */
  public void sendSnykAlert(String issueTitle, String severity, String jiraTicketUrl) {
    int color = severity.equalsIgnoreCase("high") || severity.equalsIgnoreCase("critical") ? COLOR_RED : COLOR_YELLOW;
    String desc = String.format("**Severity:** %s\n**Jira Ticket:** [View Issue](%s)", severity, jiraTicketUrl);
    sendEmbedAlert("Snyk Vulnerability Detected: " + issueTitle, desc, color);
  }

  /**
   * Sends a notification when an automated PR is created by AI.
   */
  public void sendPrCreatedAlert(String branchName, String prUrl, String vercelDetailUrl) {
    String desc = String.format(
        "**Branch:** `%s`\n**Pull Request:** [GitHub PR](%s)\n**Review & Approve:** [Vercel Dashboard](%s)", branchName,
        prUrl, vercelDetailUrl);
    sendEmbedAlert("Auto-Healing PR Created \uD83D\uDEE0\uFE0F", desc, COLOR_YELLOW);
  }

  /**
   * Sends a notification when a vulnerability fix is approved and merged.
   */
  public void sendMergeSuccessAlert(String issueTitle, String prUrl) {
    String desc = String.format("**Issue Fixed:** %s\n**Pull Request Merged:** [GitHub PR](%s)", issueTitle, prUrl);
    sendEmbedAlert("Fix Successfully Merged ✅", desc, COLOR_GREEN);
  }
}
