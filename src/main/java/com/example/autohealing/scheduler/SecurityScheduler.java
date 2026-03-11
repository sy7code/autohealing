package com.example.autohealing.scheduler;

import com.example.autohealing.service.AzureDetectionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * 정기적으로 Azure 인프라 보안 설정을 점검하는 스케줄러.
 *
 * <p>
 * 코드 취약점과 달리 인프라 설정은 의도된 변경일 수 있으므로,
 * 자동 수정을 수행하지 않고 위험 감지 시 로그만 기록합니다.
 * 실제 알림(Jira/Discord)은 GitHub Webhook 파이프라인에서 수행됩니다.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SecurityScheduler {

  private final AzureDetectionService azureDetectionService;

  /**
   * 5분마다 Azure Storage Account의 퍼블릭 액세스 설정을 점검합니다.
   * 위험이 발견되어도 자동으로 설정을 변경하지 않고 로그만 남깁니다.
   * (Manual Review Mode)
   */
  @Scheduled(fixedRate = 300000) // 5분 = 300,000ms
  public void detectAzureStorageRisks() {
    log.info("[Scheduler] Azure Storage 보안 점검 시작...");
    try {
      List<Map<String, Object>> risks = azureDetectionService.scan(null);

      if (!risks.isEmpty()) {
        log.warn("[Scheduler] ⚠️ {}건의 인프라 위험이 감지되었습니다. 수동 검토가 필요합니다.", risks.size());
        risks.forEach(risk -> log.warn("[Scheduler] - [{}] {}", risk.get("severity"), risk.get("title")));
      } else {
        log.info("[Scheduler] ✅ 인프라 점검 완료. 위험 없음.");
      }
    } catch (Exception e) {
      log.error("[Scheduler] Azure 점검 중 오류: {}", e.getMessage(), e);
    }
  }
}
