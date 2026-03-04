package com.example.autohealing.service;

import com.azure.core.credential.TokenCredential;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.profile.AzureProfile;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.resourcemanager.AzureResourceManager;
import com.azure.resourcemanager.storage.models.StorageAccount;
import com.example.autohealing.entity.SecurityLog;
import com.example.autohealing.repository.SecurityLogRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class AzureDetectionService {

  @Value("${azure.subscription-id}")
  private String subscriptionId;

  @Value("${azure.storage-account:autohealing2026}")
  private String resourceName;

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
      StorageAccount storageAccount = azure.storageAccounts().list().stream()
          .filter(sa -> resourceName.equals(sa.name()))
          .findFirst()
          .orElseThrow(() -> new RuntimeException("Storage account '" + resourceName + "' not found"));

      // 3. 공용 액세스 확인
      boolean isPublicAccessAllowed = Boolean.TRUE.equals(storageAccount.innerModel().allowBlobPublicAccess());

      if (isPublicAccessAllowed) {
        log.warn("⚠️ [Risk Detected] Storage Account '{}' allows public access.", resourceName);

        // 4. DB에 'Detected' 상태로 로그 저장
        SecurityLog logEntry = new SecurityLog(resourceName, "Anonymous Access Enabled", "High", "Detected");
        logEntry = securityLogRepository.save(logEntry);
        log.info("✅ Security Log Saved: ID={}, Status={}", logEntry.getId(), logEntry.getStatus());

        // 5. 자동 치료 (Auto-Healing): 공용 액세스 비활성화
        log.info("🛠️ Auto-Healing initiated...");

        // storageAccount.update().withAllowBlobPublicAccess(false).apply();
        storageAccount.update().disableBlobPublicAccess().apply();

        log.info("✨ Storage Account updated: Public Access DISABLED (Simulated).");

        // 6. DB 로그 업데이트 ('Resolved')
        logEntry.setStatus("Resolved");
        securityLogRepository.save(logEntry);
        log.info("✅ Security Log Updated: Status=Resolved");

        return true; // Risk found and healed
      } else {
        log.info("✅ [Secure] Storage Account '{}' public access is disabled.", resourceName);
        return false; // No risk
      }

    } catch (Exception e) {
      throw new RuntimeException("Failed to process Azure storage security check: " + e.getMessage(), e);
    }
  }
}
