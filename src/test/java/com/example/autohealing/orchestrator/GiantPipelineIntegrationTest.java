package com.example.autohealing.orchestrator;

import com.example.autohealing.ai.AiRemediationResult;
import com.example.autohealing.ai.AiRemediationService;
import com.example.autohealing.client.SnykCliScannerService;
import com.example.autohealing.entity.SecurityLog;
import com.example.autohealing.parser.dto.UnifiedIssue;
import com.example.autohealing.parser.dto.UnifiedIssue.SeverityLevel;
import com.example.autohealing.repository.SecurityLogRepository;
import com.example.autohealing.service.CodeValidatorService;
import com.example.autohealing.service.DiscordNotificationService;
import com.example.autohealing.service.GithubService;
import com.example.autohealing.service.JiraService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * [Task 2] 거대 파이프라인 통합 테스트 (Giant Pipeline Integration Test)
 * Snyk -> AI(Gemini) -> Jira -> Github -> Discord 로 이어지는 전체 워크플로우 분석 및 검증.
 */
@SpringBootTest
@ActiveProfiles("test")
public class GiantPipelineIntegrationTest {

  @Autowired
  private SecurityOrchestrator orchestrator;

  @MockitoBean
  private SnykCliScannerService snykCliScannerService;

  @MockitoBean
  private AiRemediationService aiRemediationService;

  @MockitoBean
  private JiraService jiraService;

  @MockitoBean
  private GithubService githubService;

  @MockitoBean
  private CodeValidatorService codeValidatorService;

  @MockitoBean
  private SecurityLogRepository securityLogRepository;

  @MockitoBean
  private DiscordNotificationService discordNotificationService;

  @Test
  @DisplayName("전체 보안 취축점 자동 수정 파이프라인 E2E 흐름 검증")
  void testEndToEndGiantPipelineFlow() throws Exception {
    // [Given] 1. Snyk에서 취약점 1건 발견 상황 시뮬레이션
    UnifiedIssue mockIssue = UnifiedIssue.builder()
        .id("SNYK-JAVA-SPRING-12345")
        .title("Insecure Deserialization in Spring")
        .severity(SeverityLevel.CRITICAL)
        .description("Package Path: src/main/java/com/example/Vulnerable.java\nVulnerability detail description...")
        .source("SNYK")
        .build();

    when(snykCliScannerService.scan(anyString())).thenReturn(List.of(mockIssue));

    // [Given] 2. AI 수정 서비스가 패치 코드를 성공적으로 생성했다고 가정
    AiRemediationResult mockAiResult = new AiRemediationResult(
        "public class Secure { /* fixed code */ }",
        "Fixed insecure deserialization by adding input validation.");
    when(aiRemediationService.fixCode(anyString(), anyString())).thenReturn(mockAiResult);
    when(aiRemediationService.providerName()).thenReturn("Gemini-Prod");

    // [Given] 3. 컴파일 검증 성공 가정
    when(codeValidatorService.validateCode(anyString(), anyString())).thenReturn(null);

    // [Given] 4. Jira 티켓 생성 ID 반환 모킹
    when(jiraService.createIssue(anyString(), anyString())).thenReturn("SCRUM-101");
    when(jiraService.createIssue(anyString(), anyString(), anyString(), anyList())).thenReturn("SCRUM-102");

    // [Given] 5. Github PR 생성 번호 반환 모킹
    when(githubService.createPullRequest(any(), anyString(), anyString(), anyString())).thenReturn(777);
    when(githubService.getRepoName()).thenReturn("sy7code/auto-healing-demo");

    // [Given] 6. DB 저장 시 ID 생성을 위해 모킹 (실제 DB 사용하는 대신 Mockito 사용)
    SecurityLog savedLog = new SecurityLog("repo", "title", "CRITICAL", "PENDING");
    savedLog.setId(1L);
    when(securityLogRepository.save(any(SecurityLog.class))).thenReturn(savedLog);
    when(securityLogRepository.findById(1L)).thenReturn(Optional.of(savedLog));

    // [When] 파이프라인 실행
    // 1단계: 분석 시작 (Jira 분석중 티켓 생성)
    String parentIssueKey = orchestrator.startAnalysis("my-repo", "sha-123", "tester");
    assertThat(parentIssueKey).isEqualTo("SCRUM-101");

    // 2단계: 비동기 작업 실행 (테스트에서는 직접 호출하여 결과를 즉시 확인)
    orchestrator.runSnykScanAndUpdate(parentIssueKey, "my-repo", "/tmp/scan");

    // [Then] 전체 파이프라인 단계별 호출 검증 (비동기 처리를 위해 timeout 속성 적용)
    // 1. Snyk 스캔 호출 확인
    verify(snykCliScannerService, timeout(2000)).scan(eq("/tmp/scan"));

    // 2. AI 수정 서비스 호출 확인 (Critical 등급이므로 호출되어야 함)
    verify(aiRemediationService, timeout(2000)).fixCode(anyString(), contains("SNYK-JAVA-SPRING-12345"));

    // 3. 컴파일 검증 호출 확인
    verify(codeValidatorService, timeout(2000)).validateCode(eq(mockAiResult.getFixedCode()), anyString());

    // 4. Jira 개별 취약점 티켓 생성 및 진행 상태 변경 확인
    verify(jiraService, timeout(2000)).createIssue(eq(mockIssue.getTitle()), anyString(), eq("CRITICAL"), anyList());
    verify(jiraService, timeout(2000)).transitionIssue(eq("SCRUM-102"), any());

    // 5. Github PR 생성 확인
    verify(githubService, timeout(2000)).createPullRequest(eq(mockIssue), anyString(), eq(mockAiResult.getFixedCode()),
        anyString());

    // 6. Discord 알림 발송 확인 (Snyk 발견 시, PR 생성 시)
    verify(discordNotificationService, timeout(2000).atLeastOnce()).sendSnykAlert(anyString(), anyString(),
        anyString());
    verify(discordNotificationService, timeout(2000)).sendPrCreatedAlert(anyString(), contains("777"), anyString());

    // 7. DB 최종 결과 업데이트 루틴 확인
    verify(securityLogRepository, timeout(2000).atLeast(2)).save(any(SecurityLog.class));
  }
}
