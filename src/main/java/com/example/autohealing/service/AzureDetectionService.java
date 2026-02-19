package com.example.autohealing.service;

import com.azure.core.credential.TokenCredential;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.profile.AzureProfile;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.resourcemanager.AzureResourceManager;
import com.azure.resourcemanager.storage.models.StorageAccount;
import com.example.autohealing.entity.SecurityLog;
import com.example.autohealing.repository.SecurityLogRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class AzureDetectionService {

  @Value("${AZURE_SUBSCRIPTION_ID}")
  private String subscriptionId;

  private final SecurityLogRepository securityLogRepository;

  public AzureDetectionService(SecurityLogRepository securityLogRepository) {
    this.securityLogRepository = securityLogRepository;
  }

  public boolean checkAndHealStorageAccount() {
    try {
      // 1. 인증 및 클라이언트 생성
      TokenCredential credential = new DefaultAzureCredentialBuilder().build();
      AzureProfile profile = new AzureProfile(AzureEnvironment.AZURE);

      AzureResourceManager azure = AzureResourceManager.configure()
          .authenticate(credential, profile)
          .withSubscription(subscriptionId);

      // 2. 저장소 계정 찾기
      String resourceName = "autohealing2026";
      StorageAccount storageAccount = azure.storageAccounts().list().stream()
          .filter(sa -> resourceName.equals(sa.name()))
          .findFirst()
          .orElseThrow(() -> new RuntimeException("Storage account '" + resourceName + "' not found"));

      // 3. 공용 액세스 확인
      boolean isPublicAccessAllowed = Boolean.TRUE.equals(storageAccount.innerModel().allowBlobPublicAccess());

      if (isPublicAccessAllowed) {
        System.out.println("⚠️ [Risk Detected] Storage Account '" + resourceName + "' allows public access.");

        // 4. DB에 'Detected' 상태로 로그 저장
        SecurityLog log = new SecurityLog(resourceName, "Anonymous Access Enabled", "High", "Detected");
        log = securityLogRepository.save(log);
        System.out.println("✅ Security Log Saved: ID=" + log.getId() + ", Status=" + log.getStatus());

        // 5. 자동 치료 (Auto-Healing): 공용 액세스 비활성화
        System.out.println("🛠️ Auto-Healing initiated...");

        // TODO: 'withAllowBlobPublicAccess' 메서드가 SDK 버전에 따라 다를 수 있어 잠시 주석 처리합니다.
        // 수정을 위해 올바른 메서드로 변경 시도: disableBlobPublicAccess()
        // storageAccount.update().withAllowBlobPublicAccess(false).apply();
        storageAccount.update().disableBlobPublicAccess().apply();

        System.out.println("✨ Storage Account updated: Public Access DISABLED (Simulated).");

        // 6. DB 로그 업데이트 ('Resolved')
        log.setStatus("Resolved");
        securityLogRepository.save(log);
        System.out.println("✅ Security Log Updated: Status=Resolved");

        return true; // Risk found and healed
      } else {
        System.out.println("✅ [Secure] Storage Account '" + resourceName + "' public access is disabled.");
        return false; // No risk
      }

    } catch (Exception e) {
      throw new RuntimeException("Failed to process Azure storage security check: " + e.getMessage(), e);
    }
  }
}
