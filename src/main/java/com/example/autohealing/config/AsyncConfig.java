package com.example.autohealing.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

/**
 * @Async 메서드 실행에 사용할 스레드 풀 설정.
 *
 *        <p>
 *        SecurityOrchestrator의 비동기 Snyk 스캔이 이 풀에서 실행됩니다.
 *        웹훅 요청 스레드와 완전히 분리되어 즉시 202 Accepted를 반환할 수 있습니다.
 */
@EnableAsync
@Configuration
public class AsyncConfig {

  /**
   * "securityTaskExecutor" 이름으로 등록되는 전용 스레드 풀.
   *
   * <ul>
   * <li>corePoolSize : 평시 유지 스레드 수</li>
   * <li>maxPoolSize : 최대 병렬 스캔 수 (Snyk 스캔은 I/O 대기가 길어 넉넉히 설정)</li>
   * <li>queueCapacity : 대기 큐 크기</li>
   * </ul>
   */
  @Bean(name = "securityTaskExecutor")
  public Executor securityTaskExecutor() {
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(4);
    executor.setMaxPoolSize(10);
    executor.setQueueCapacity(50);
    executor.setThreadNamePrefix("security-scan-");
    executor.setWaitForTasksToCompleteOnShutdown(true);
    executor.setAwaitTerminationSeconds(30);
    executor.initialize();
    return executor;
  }
}
