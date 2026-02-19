package com.example.autohealing.scheduler;

import com.example.autohealing.service.AzureDetectionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class SecurityScheduler {

  private final AzureDetectionService azureDetectionService;

  @Scheduled(fixedRate = 300000) // 5분 = 300,000ms
  public void detectAzureStorageRisks() {
    log.info("Starting Azure Storage security check...");
    try {
      boolean healed = azureDetectionService.checkAndHealStorageAccount();

      if (healed) {
        log.info("RISK DETECTED AND HEALED: Storage account 'autohealing2026' was public, now secured.");
      } else {
        log.info("No risks detected. Storage account is secure.");
      }
    } catch (Exception e) {
      log.error("Error during Azure security check: {}", e.getMessage(), e);
    }
  }
}
