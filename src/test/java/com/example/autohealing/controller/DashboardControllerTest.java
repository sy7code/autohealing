package com.example.autohealing.controller;

import com.example.autohealing.entity.SecurityLog;
import com.example.autohealing.repository.SecurityLogRepository;
import com.example.autohealing.service.GithubService;
import com.example.autohealing.service.JiraService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import com.example.autohealing.service.DiscordNotificationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;

@ExtendWith(MockitoExtension.class)
class DashboardControllerTest {

  @Mock
  private SecurityLogRepository securityLogRepository;

  @Mock
  private JiraService jiraService;

  @Mock
  private GithubService githubService;

  @Mock
  private DiscordNotificationService discordNotificationService;

  @InjectMocks
  private DashboardController dashboardController;

  private SecurityLog dummyLog;

  @BeforeEach
  void setUp() {
    dummyLog = new SecurityLog();
    dummyLog.setId(1L);
    dummyLog.setPrNumber(123);
    dummyLog.setApproved(false);
    // Jira key and other fields can be left null/empty for simple testing unless
    // required.
  }

  @Test
  @DisplayName("PR 테스트가 성공(success)했을 때 승인 성공")
  void approveVulnerability_ciSuccess_mergesPr() {
    // given
    given(securityLogRepository.findById(1L)).willReturn(Optional.of(dummyLog));
    given(githubService.isPrTestsSuccessful(null, 123)).willReturn(true);
    given(githubService.mergePullRequest(null, 123)).willReturn(true);
    given(githubService.getDefaultRepoName()).willReturn("test/repo");

    // when
    ResponseEntity<?> response = dashboardController.approveVulnerability(1L);

    // then
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).isNotNull();
    if (response.getBody() instanceof Map<?, ?> body) {
      assertThat(body.get("approved")).isEqualTo(true);
      assertThat(body.get("prMerged")).isEqualTo(true);
    }

    verify(githubService).isPrTestsSuccessful(null, 123);
    verify(githubService).mergePullRequest(null, 123);
  }

  @Test
  @DisplayName("PR 테스트가 실패(진행중 등)했을 때 승인 거부 (400 Bad Request)")
  void approveVulnerability_ciFailure_rejectsMerge() {
    // given
    given(securityLogRepository.findById(1L)).willReturn(Optional.of(dummyLog));
    given(githubService.isPrTestsSuccessful(null, 123)).willReturn(false);

    // when
    ResponseEntity<?> response = dashboardController.approveVulnerability(1L);

    // then
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(response.getBody()).isNotNull();
    assertThat((String) response.getBody()).contains("CI 테스트가 아직 진행 중이거나 실패했습니다. 잠시 후 다시 시도해주세요.");

    verify(githubService).isPrTestsSuccessful(null, 123);
    // 머지는 호출되지 않아야 함
    verify(githubService, never()).mergePullRequest(org.mockito.ArgumentMatchers.anyString(), anyInt());
  }
}
