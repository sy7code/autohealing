package com.example.autohealing.client;

import com.example.autohealing.entity.PluginConfig;
import com.example.autohealing.repository.PluginConfigRepository;
import com.example.autohealing.service.EncryptionService;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

/**
 * 여러 개의 ScannerService(정적 + 동적)를 병렬로 실행하고 취합하는 매니저.
 */
@Service
public class ScannerManager {

  private static final Logger log = LoggerFactory.getLogger(ScannerManager.class);

  private final ApplicationContext context;
  private final PluginConfigRepository pluginConfigRepository;
  private final EncryptionService encryptionService;
  private final RestTemplate restTemplate;

  // v12: 병렬 실행을 위한 공유 ThreadPool, v13: Graceful Shutdown을 위해 필드 보관
  private ExecutorService executorService;

  // Spring Bean으로 등록된 정적 스캐너 (예: 기존 SnykClient)
  private List<SecurityScannerService> staticScanners;

  public ScannerManager(ApplicationContext context,
      PluginConfigRepository pluginConfigRepository,
      EncryptionService encryptionService,
      RestTemplate restTemplate) {
    this.context = context;
    this.pluginConfigRepository = pluginConfigRepository;
    this.encryptionService = encryptionService;
    this.restTemplate = restTemplate;
  }

  @PostConstruct
  public void init() {
    // v13 Fix: Thread Pool 초기화 (재시작 시 누수 방지용)
    this.executorService = Executors.newFixedThreadPool(Math.min(Runtime.getRuntime().availableProcessors(), 4));

    // 정적 빈 스캐너 수집 (SecurityScannerService 인터페이스를 구현한 모든 빈)
    Map<String, SecurityScannerService> beans = context.getBeansOfType(SecurityScannerService.class);
    this.staticScanners = new ArrayList<>(beans.values());
    log.info("정적 스캐너 {}개 로드됨.", staticScanners.size());
  }

  @PreDestroy
  public void shutdown() {
    // v13 Fix: 치명적인 리소스 누수(Thread Leak) 방지를 위한 명시적 종료
    if (executorService != null && !executorService.isShutdown()) {
      log.info("ScannerManager ExecutorService 종료 중...");
      executorService.shutdown();
      try {
        if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
          executorService.shutdownNow();
        }
      } catch (InterruptedException e) {
        executorService.shutdownNow();
        Thread.currentThread().interrupt();
      }
    }
  }

  /**
   * 등록된 모든 활성 스캐너(정적 + 동적)를 병렬로 실행하여 결과를 취합합니다.
   */
  public List<Map<String, Object>> runAllActiveScanners(String repositoryUri) {
    List<SecurityScannerService> activeScanners = new ArrayList<>(staticScanners);

    // 1. DB에서 동적 스캐너(SaaS 플러그인) 로드
    List<PluginConfig> activeDynamicConfigs = pluginConfigRepository
        .findByPluginTypeAndEnabledTrue(PluginConfig.PluginType.SCANNER);
    for (PluginConfig config : activeDynamicConfigs) {
      activeScanners.add(new GenericApiScanner(config, restTemplate, encryptionService));
    }

    if (activeScanners.isEmpty()) {
      log.warn("활성화된 스캐너가 없습니다. 스캔 종료.");
      return Collections.emptyList();
    }

    // 2. 병렬 스캔 실행
    List<CompletableFuture<List<Map<String, Object>>>> futures = activeScanners.stream()
        .map(scanner -> CompletableFuture.supplyAsync(() -> safeScan(scanner, repositoryUri), executorService))
        .toList();

    // 3. 결과 취합
    List<Map<String, Object>> allVulns = new ArrayList<>();
    for (CompletableFuture<List<Map<String, Object>>> future : futures) {
      try {
        // v12 Fix: 타임아웃 30초 설정 및 Poison Pill 격리 (다른 스캐너 장애가 전체를 죽이지 않음)
        List<Map<String, Object>> result = future.get(30, TimeUnit.SECONDS);
        if (result != null) {
          allVulns.addAll(result);
        }
      } catch (TimeoutException e) {
        log.error("스캐너 응답 지연 (30초 초과), 건너뜁니다.");
      } catch (Exception e) {
        log.error("스캐너 실행 중 오류 발생: {}", e.getMessage());
      }
    }

    return allVulns;
  }

  private List<Map<String, Object>> safeScan(SecurityScannerService scanner, String repositoryUri) {
    try {
      return scanner.scan(repositoryUri);
    } catch (Exception e) {
      log.error("[{}] 스캐너 내부 오류 방어: {}", scanner.providerName(), e.getMessage());
      return Collections.emptyList();
    }
  }
}
