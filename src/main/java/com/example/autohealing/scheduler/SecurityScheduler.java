package com.example.autohealing.scheduler;

import com.example.autohealing.service.AzureDetectionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 정기적으로 보안 취약점을 검사하는 스케줄러.
 *
 * <p>
 * 여기서는 5분마다 Azure Storage Account의 Public Access 설정 여부를
 * 확인하고, 발견 즉시 비활성화하는 자동 치유 로직을 실행합니다.
 */
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
