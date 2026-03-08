package com.example.autohealing.controller;

import com.example.autohealing.orchestrator.SecurityOrchestrator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Map;

/**
 * GitHub Webhook 수신 엔드포인트.
 *
 * <h3>WebFlux 비동기 처리 원칙</h3>
 * WebFlux 환경에서는 nio 이벤트 루프 스레드에서 block()을 호출할 수 없습니다.
 * → {@code Mono.fromCallable(...).subscribeOn(Schedulers.boundedElastic())}
 * 패턴으로
 * 블로킹 작업(Jira API 호출)을 전용 스레드 풀로 위임합니다.
 *
 * <h3>흐름</h3>
 * 
 * <pre>
 * POST /api/webhook/github
 *   → [boundedElastic] Step 1 (동기): "분석 중" Jira 티켓 생성
 *   → 즉시 202 Accepted 반환
 *   → [securityTaskExecutor] Step 2 (@Async): Snyk 스캔 후 Jira 티켓 업데이트
 * </pre>
 */
@Slf4j
@RestController
@RequestMapping("/api/webhook")
@RequiredArgsConstructor
public class GithubWebhookController {

  private final SecurityOrchestrator orchestrator;

  /**
   * GitHub Push 이벤트 수신 처리.
   *
   * @param payload GitHub Webhook JSON 페이로드
   * @return 202 Accepted (비동기 Mono 반환으로 nio 스레드 점유 없음)
   */
  @PostMapping("/github")
  public Mono<ResponseEntity<Map<String, String>>> handleGithubWebhook(
      @RequestBody Map<String, Object> payload) {

    // PR Merge 이벤트 처리 분기
    if (payload.containsKey("pull_request")) {
      return handlePullRequestEvent(payload);
    }

    String repoName = extractRepoName(payload);
    String commitId = extractCommitId(payload);
    String committer = extractCommitter(payload);

    log.info("[Webhook] GitHub 이벤트 수신 - repo={}, commit={}, committer={}",
        repoName, commitId, committer);

    // ── boundedElastic 스레드에서 블로킹 Jira API 호출 ───────────────────
    return Mono.fromCallable(() -> orchestrator.startAnalysis(repoName, commitId, committer))
        .subscribeOn(Schedulers.boundedElastic()) // block() 허용 스레드로 이동
        .map(issueKey -> {
          if (issueKey == null) {
            log.error("[Webhook] Jira 초기 티켓 생성 실패 - repo={}", repoName);
            ResponseEntity<Map<String, String>> errorRes = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("status", "error", "message", "Jira 티켓 생성에 실패했습니다."));
            return errorRes;
          }
          log.info("[Webhook] 초기 Jira 티켓 생성 완료: {}", issueKey);

          // Step 2: 비동기 Snyk 스캔 시작 (별도 스레드, 즉시 반환)
          orchestrator.runScanAndUpdate(issueKey, repoName);

          ResponseEntity<Map<String, String>> okRes = ResponseEntity.accepted()
              .body(Map.of(
                  "status", "accepted",
                  "message", "보안 분석이 시작되었습니다. 결과는 Jira 티켓에 자동 업데이트됩니다.",
                  "issueKey", issueKey,
                  "repo", repoName,
                  "commit", commitId,
                  "committer", committer));
          return okRes;
        })
        .onErrorResume(ex -> {
          log.error("[Webhook] 처리 중 예외 발생 - repo={}", repoName, ex);
          ResponseEntity<Map<String, String>> errorRes = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
              .body(Map.of("status", "error", "message", "서버 내부 오류: " + ex.getMessage()));
          return Mono.just(errorRes);
        });
  }

  /**
   * 로컬 테스트용 엔드포인트. 실제 GitHub 페이로드 구조로 전체 파이프라인 트리거.
   */
  @PostMapping("/github/test")
  public Mono<ResponseEntity<Map<String, String>>> testWebhook() {
    log.info("[Webhook] 테스트 트리거 호출됨");
    return handleGithubWebhook(Map.of(
        "repository", Map.of("full_name", "my-org/auto-healing-demo"),
        "after", "abc1234def5678",
        "pusher", Map.of("name", "test-user"),
        "head_commit", Map.of(
            "id", "abc1234def5678",
            "message", "test commit",
            "author", Map.of("username", "test-user"))));
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – 페이로드 파싱 헬퍼
  // ─────────────────────────────────────────────────────────────────────────

  private Mono<ResponseEntity<Map<String, String>>> handlePullRequestEvent(Map<String, Object> payload) {
    Object actionObj = payload.get("action");
    Object prObj = payload.get("pull_request");

    if (actionObj instanceof String action && "closed".equals(action) && prObj instanceof Map<?, ?> pr) {
      if (Boolean.TRUE.equals(pr.get("merged"))) {
        Object bodyObj = pr.get("body");
        log.info("[Webhook] PR Merge 감지됨");

        if (bodyObj instanceof String body && body.contains("**🔗 연동된 Jira 티켓:**")) {
          int idx = body.indexOf("**🔗 연동된 Jira 티켓:**") + "**🔗 연동된 Jira 티켓:**".length();
          String jiraKey = body.substring(idx).trim().split("\\s+")[0];

          if (!jiraKey.isBlank()) {
            log.info("[Webhook] PR 본문에서 Jira 티켓 추출: {}. 상태 'Done'으로 전환 시도.", jiraKey);
            return Mono.fromCallable(() -> orchestrator.completeJiraTicket(jiraKey))
                .subscribeOn(Schedulers.boundedElastic())
                .map(success -> {
                  if (Boolean.TRUE.equals(success)) {
                    return ResponseEntity
                        .ok(Map.of("status", "success", "message", jiraKey + " 상태 업데이트 완료"));
                  } else {
                    return ResponseEntity
                        .ok(Map.of("status", "failed", "message", jiraKey + " 상태 업데이트 실패"));
                  }
                });
          }
        }
      }
    }
    return Mono.just(ResponseEntity.ok(Map.of("status", "ignored", "message", "PR 이벤트 무시처리")));
  }

  private String extractRepoName(Map<String, Object> payload) {
    Object repoObj = payload.get("repository");
    if (repoObj instanceof Map<?, ?> repoMap) {
      Object fullName = repoMap.get("full_name");
      if (fullName instanceof String s && !s.isBlank()) {
        return s;
      }
    }
    return "unknown-repo";
  }

  private String extractCommitId(Map<String, Object> payload) {
    // GitHub 실제 push 이벤트: "after" 필드
    Object after = payload.get("after");
    if (after instanceof String s && !s.isBlank()) {
      return s.length() > 8 ? s.substring(0, 8) : s;
    }
    // 테스트 페이로드: "head_commit.id" 필드
    Object headCommitObj = payload.get("head_commit");
    if (headCommitObj instanceof Map<?, ?> headCommit) {
      Object idObj = headCommit.get("id");
      if (idObj instanceof String s && !s.isBlank()) {
        return s.length() > 8 ? s.substring(0, 8) : s;
      }
    }
    return "unknown-commit";
  }

  private String extractCommitter(Map<String, Object> payload) {
    // GitHub 실제 push 이벤트: "pusher.name" 필드
    Object pusherObj = payload.get("pusher");
    if (pusherObj instanceof Map<?, ?> pusher) {
      Object nameObj = pusher.get("name");
      if (nameObj instanceof String s && !s.isBlank()) {
        return s;
      }
    }

    // 테스트 페이로드: "head_commit.author.username" 필드
    Object headCommitObj = payload.get("head_commit");
    if (headCommitObj instanceof Map<?, ?> headCommit) {
      Object authorObj = headCommit.get("author");
      if (authorObj instanceof Map<?, ?> author) {
        Object usernameObj = author.get("username");
        if (usernameObj == null) {
          usernameObj = author.get("name");
        }
        if (usernameObj instanceof String s && !s.isBlank()) {
          return s;
        }
      }
    }
    return "unknown";
  }
}
