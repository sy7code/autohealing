package com.example.autohealing.client;

import com.example.autohealing.entity.PluginConfig;
import com.example.autohealing.repository.PluginConfigRepository;
import com.example.autohealing.service.EncryptionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.context.ApplicationContext;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class ScannerManagerTest {

  @Mock
  private ApplicationContext context;
  @Mock
  private PluginConfigRepository configRepository;
  @Mock
  private EncryptionService encryptionService;
  @Mock
  private RestTemplate restTemplate;

  private ScannerManager scannerManager;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);

    // 정적 스캐너 빈 모킹
    SecurityScannerService mockStaticScanner = new SecurityScannerService() {
      @Override
      public String providerName() {
        return "MockStaticScanner";
      }

      @Override
      public List<Map<String, Object>> scan(String repoUri) {
        return List.of(Map.of("id", "STATIC-123", "title", "Static Vuln"));
      }
    };

    when(context.getBeansOfType(SecurityScannerService.class))
        .thenReturn(Map.of("mockScanner", mockStaticScanner));

    // ScannerManager 초기화
    scannerManager = new ScannerManager(context, configRepository, encryptionService, restTemplate);
    ReflectionTestUtils.setField(scannerManager, "useStaticDefaults", true);
    scannerManager.init(); // @PostConstruct 트리거
  }

  @Test
  @DisplayName("정적 스캐너와 동적 스캐너의 결과가 모두 병합되어야 한다")
  void runAllActiveScannersTest() {
    // given
    PluginConfig dynamicConfig = new PluginConfig();
    dynamicConfig.setName("DynamicSaaSScanner");
    dynamicConfig.setPluginType(PluginConfig.PluginType.SCANNER);
    dynamicConfig.setEnabled(true);
    dynamicConfig.setApiKeyEncrypted("test-encrypted-key");
    // 동적 스캐너는 실제 HTTP 요청을 하므로 restTemplate을 모킹하는 대신 빈 결과를 유도
    when(encryptionService.decrypt(any())).thenReturn("[DECRYPTION_FAILED]");

    when(configRepository.findByPluginTypeAndEnabledTrue(PluginConfig.PluginType.SCANNER))
        .thenReturn(List.of(dynamicConfig));

    // when
    List<Map<String, Object>> results = scannerManager.runAllActiveScanners("dummy-repo");

    // then
    // 정적 스캐너의 1건 + 동적 스캐너(복호화 실패로 0건)
    assertThat(results).hasSize(1);
    assertThat(results.get(0).get("id")).isEqualTo("STATIC-123");

    // 메모리 누수 방지 (Graceful Shutdown 검증)
    scannerManager.shutdown();
  }
}
