package com.example.autohealing.service;

import com.azure.core.credential.TokenCredential;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.profile.AzureProfile;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.resourcemanager.AzureResourceManager;
import com.azure.resourcemanager.storage.models.StorageAccount;
import com.example.autohealing.client.SecurityScannerService;
import com.example.autohealing.common.ScannerConstants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Azure 클라우드 인프라의 보안 설정 위험을 탐지하는 CSPM(Cloud Security Posture Management) 스캐너.
 *
 * <p>
 * 코드 취약점(SAST)과 달리 인프라 설정은 의도된 변경일 수 있으므로,
 * 자동 수정을 수행하지 않고 위험 감지 결과만 반환합니다.
 * 오케스트레이터가 Jira/Discord 알림으로 수동 리뷰를 유도합니다.
 *
 * <h3>현재 탐지 규칙</h3>
 * <ul>
 * <li>Azure Storage Account의 퍼블릭 액세스 허용 여부</li>
 * </ul>
 */
@Slf4j
@Service
public class AzureDetectionService implements SecurityScannerService {

  @Value("${azure.subscription-id:}")
  private String subscriptionId;

  @Value("${azure.storage-account:autohealing2026}")
  private String resourceName;

  public AzureDetectionService() {
  }

  @Override
  public String providerName() {
    return ScannerConstants.SOURCE_AZURE_CSPM;
  }

  /**
   * Azure 인프라 보안 점검을 수행합니다.
   * Subscription ID가 설정되지 않은 경우 비용 절감을 위해 즉시 건너뜁니다.
   *
   * @param repositoryUri 사용되지 않음 (인프라 스캐너는 저장소 무관)
   * @return 발견된 인프라 취약점 목록
   */
  @Override
  public List<Map<String, Object>> scan(String repositoryUri) {
    log.info("[Azure-CSPM] 인프라 보안 점검 시작...");
    List<Map<String, Object>> results = new ArrayList<>();

    try {
      if (subscriptionId == null || subscriptionId.isBlank()) {
        log.warn("[Azure-CSPM] Subscription ID가 설정되지 않아 점검을 건너뜁니다.");
        return results;
      }

      boolean hasRisk = detectStorageAccountRisk();

      if (hasRisk) {
        Map<String, Object> issue = new HashMap<>();
        issue.put("id", "AZURE-STORAGE-PUBLIC-ACCESS");
        issue.put("title", "Azure Storage Account Public Access Allowed");
        issue.put("severity", "HIGH");
        issue.put("description",
            "Storage Account '" + resourceName + "' has public access enabled. " +
                "이것이 의도된 설정인지 확인하십시오. 보안을 위해 비활성화를 권장합니다.");
        issue.put("scannerName", providerName());
        results.add(issue);
      }
    } catch (Exception e) {
      log.error("[Azure-CSPM] 점검 중 오류: {}", e.getMessage());
    }

    return results;
  }

  /**
   * Azure Storage Account의 퍼블릭 액세스 허용 여부를 확인합니다.
   * DB 저장 및 자동 수정은 수행하지 않으며, 위험 감지 여부만 반환합니다.
   * (DB 저장 및 알림 책임은 SecurityOrchestrator에게 위임)
   *
   * @return true: 위험 설정 감지됨 / false: 안전
   */
  boolean detectStorageAccountRisk() {
    try {
      // 1. 인증 및 클라이언트 생성
      TokenCredential credential = new DefaultAzureCredentialBuilder().build();
      AzureProfile profile = new AzureProfile(AzureEnvironment.AZURE);

      AzureResourceManager azure = AzureResourceManager.configure()
          .authenticate(credential, profile)
          .withSubscription(subscriptionId);

      // 2. 저장소 계정 찾기
      StorageAccount storageAccount = azure.storageAccounts().list().stream()
          .filter(sa -> resourceName.equals(sa.name()))
          .findFirst()
          .orElseThrow(() -> new RuntimeException("Storage account '" + resourceName + "' not found"));

      // 3. 공용 액세스 허용 여부 확인
      boolean isPublicAccessAllowed = Boolean.TRUE.equals(storageAccount.innerModel().allowBlobPublicAccess());

      if (isPublicAccessAllowed) {
        log.warn("⚠️ [Risk Detected] Storage Account '{}' allows public access.", resourceName);
        log.info("📢 Manual Review Mode: 오케스트레이터를 통해 Jira/Discord 알림이 생성됩니다.");
        return true;
      } else {
        log.info("✅ [Secure] Storage Account '{}' public access is disabled.", resourceName);
        return false;
      }

    } catch (Exception e) {
      throw new RuntimeException("Failed to detect Azure storage security risk: " + e.getMessage(), e);
    }
  }
}
