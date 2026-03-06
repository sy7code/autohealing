package com.example.autohealing.controller;

import com.example.autohealing.orchestrator.SecurityOrchestrator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class GithubWebhookControllerTest {

  @Mock
  private SecurityOrchestrator orchestrator;

  @InjectMocks
  private GithubWebhookController controller;

  @Test
  @DisplayName("Push 이벤트 수신 시 SecurityOrchestrator 를 호출하고 Accepted 반환")
  void handleGithubWebhook_pushEvent_returnsAccepted() {
    // given
    Map<String, Object> payload = Map.of(
        "repository", Map.of("full_name", "test-user/test-repo"),
        "after", "1234567890abcdef",
        "pusher", Map.of("name", "tester"));
    given(orchestrator.startAnalysis("test-user/test-repo", "12345678", "tester")).willReturn("TEST-123");

    // when
    Mono<ResponseEntity<Map<String, String>>> monoResult = controller.handleGithubWebhook(payload);
    ResponseEntity<Map<String, String>> response = monoResult.block();

    // then
    assertThat(response).isNotNull();
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
    assertThat(response.getBody()).isNotNull();
    assertThat(response.getBody().get("status")).isEqualTo("accepted");
    assertThat(response.getBody().get("issueKey")).isEqualTo("TEST-123");

    verify(orchestrator).startAnalysis("test-user/test-repo", "12345678", "tester");
    verify(orchestrator).runSnykScanAndUpdate("TEST-123", "test-user/test-repo");
  }

  @Test
  @DisplayName("PR Merge 이벤트 수신 시 Jira 티켓 완료 처리 후 OK 반환")
  void handleGithubWebhook_prMergeEvent_returnsOk() {
    // given
    Map<String, Object> payload = Map.of(
        "action", "closed",
        "pull_request", Map.of(
            "merged", true,
            "body", "This PR fixes a bug.\n**🔗 연동된 Jira 티켓:** TEST-456 "));
    given(orchestrator.completeJiraTicket("TEST-456")).willReturn(true);

    // when
    Mono<ResponseEntity<Map<String, String>>> monoResult = controller.handleGithubWebhook(payload);
    ResponseEntity<Map<String, String>> response = monoResult.block();

    // then
    assertThat(response).isNotNull();
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).isNotNull();
    assertThat(response.getBody().get("status")).isEqualTo("success");
    assertThat(response.getBody().get("message")).contains("TEST-456");

    verify(orchestrator).completeJiraTicket("TEST-456");
  }
}
