package com.example.autohealing.service;

import com.example.autohealing.parser.dto.UnifiedIssue;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * GitHub REST API 와 연동해 Branch 생성 및 Pull Request를 요청하는 서비스.
 */
@Slf4j
@Service
public class GithubService {

  private final WebClient webClient;
  private final String githubToken;
  private final String repoName;
  private final String baseBranch; // 기본값 "feature/ai-remediation-engine"

  public GithubService(
      @Value("${GITHUB_TOKEN:}") String githubToken,
      @Value("${GITHUB_REPO:}") String repoName,
      @Value("${GITHUB_BASE_BRANCH:feature/ai-remediation-engine}") String baseBranch) {
    this.webClient = WebClient.create("https://api.github.com");
    this.githubToken = githubToken;
    this.repoName = repoName;
    this.baseBranch = baseBranch;
  }

  /**
   * AI 코드가 적용된 파일 내용을 바탕으로 새 브랜치에 커밋하고 Pull Request를 생성합니다.
   *
   * @param issue        취약점 이슈 정보
   * @param originalCode 원본 소스코드
   * @param fixedCode    수정된 소스코드
   * @param explanation  AI가 작성한 원인 및 수정 내역 (한국어 설명)
   */
  public void createPullRequest(UnifiedIssue issue, String originalCode, String fixedCode, String explanation) {
    if (githubToken.isBlank() || repoName.isBlank()) {
      log.warn("[GitHub] 인증 토큰 또는 저장소 정보가 설정되지 않아 PR 생성을 건너뜁니다.");
      return;
    }

    String filePath = extractFilePath(issue.getDescription());
    if (filePath == null) {
      log.warn("[GitHub] 티켓 내용에서 파일 경로를 추출할 수 없어 PR 생성을 건너뜁니다. ID={}", issue.getId());
      return;
    }

    String safeIssueId = issue.getId().replaceAll("[^a-zA-Z0-9-]", "-");
    String newBranchName = "auto-fix-" + safeIssueId;

    log.info("[GitHub] PR 생성 프로세스 시작 - branch={}, file={}", newBranchName, filePath);

    try {
      // 1. Get base branch SHA
      String baseSha = getBranchSha(baseBranch);
      if (baseSha == null) {
        log.error("[GitHub] Base 브랜치({})의 SHA를 찾을 수 없습니다.", baseBranch);
        return;
      }

      // 2. Create new branch
      boolean branchCreated = createBranch(newBranchName, baseSha);
      if (!branchCreated) {
        log.error("[GitHub] 새 브랜치({}) 생성 실패", newBranchName);
        return;
      }

      // 3. Get existing file SHA (to update)
      String fileSha = getFileSha(newBranchName, filePath);
      if (fileSha == null) {
        log.error("[GitHub] 대상 파일({}) 조회 실패", filePath);
        return;
      }

      // 4. Update file with fixed code
      updateFile(newBranchName, filePath, fileSha, fixedCode, "fix: " + issue.getTitle() + " by AI");

      // 5. Create PR
      String prTitle = "[Auto-Healing] " + issue.getTitle();
      String prBody = String.format("""
          ## 🤖 AI 자동 취약점 수정 (Auto-Healing)

          **🔗 취약점 ID:** %s
          **📁 대상 파일:** `%s`

          Snyk가 감지한 취약점을 해결하기 위해 AI 모델이 코드를 분석하고 수정을 제안했습니다.

          ---
          ### 💡 AI 분석 및 수정 내역 요약
          %s
          ---

          자세한 이력과 원본 내역은 연동된 Jira 티켓을 확인해 주세요.
          """, issue.getId(), filePath, explanation);

      createPr(newBranchName, baseBranch, prTitle, prBody);

      log.info("[GitHub] PR 생성 완료!");

    } catch (Exception e) {
      log.error("[GitHub] PR 생성 과정 중 예외 발생", e);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private - GitHub API Helpers
  // ─────────────────────────────────────────────────────────────────────────

  private String getBranchSha(String branchName) {
    try {
      Map<?, ?> response = webClient.get()
          .uri("/repos/" + repoName + "/git/ref/heads/" + branchName)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + githubToken)
          .header(HttpHeaders.ACCEPT, "application/vnd.github.v3+json")
          .retrieve()
          .bodyToMono(Map.class)
          .block();

      if (response != null && response.containsKey("object")) {
        return (String) ((Map<?, ?>) response.get("object")).get("sha");
      }
    } catch (Exception e) {
      log.error("[GitHub API] 브랜치 SHA 조회 중 오류", e);
    }
    return null;
  }

  private boolean createBranch(String branchName, String sha) {
    try {
      webClient.post()
          .uri("/repos/" + repoName + "/git/refs")
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + githubToken)
          .header(HttpHeaders.ACCEPT, "application/vnd.github.v3+json")
          .contentType(MediaType.APPLICATION_JSON)
          .bodyValue(Map.of(
              "ref", "refs/heads/" + branchName,
              "sha", sha))
          .retrieve()
          .bodyToMono(Void.class)
          .block();
      return true;
    } catch (Exception e) {
      // 브랜치가 이미 존재하는 경우 등
      log.warn("[GitHub API] 브랜치 생성 실패 (이미 존재할 수도 있음): {}", e.getMessage());
      return false;
    }
  }

  private String getFileSha(String branchName, String filePath) {
    try {
      Map<?, ?> response = webClient.get()
          .uri("/repos/" + repoName + "/contents/" + filePath + "?ref=" + branchName)
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + githubToken)
          .header(HttpHeaders.ACCEPT, "application/vnd.github.v3+json")
          .retrieve()
          .bodyToMono(Map.class)
          .block();

      if (response != null && response.containsKey("sha")) {
        return (String) response.get("sha");
      }
    } catch (Exception e) {
      log.error("[GitHub API] 파일 SHA 조회 오류: path={}", filePath, e);
    }
    return null;
  }

  private void updateFile(String branchName, String filePath, String sha, String content, String message) {
    String base64Content = Base64.getEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8));

    webClient.put()
        .uri("/repos/" + repoName + "/contents/" + filePath)
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + githubToken)
        .header(HttpHeaders.ACCEPT, "application/vnd.github.v3+json")
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue(Map.of(
            "message", message,
            "content", base64Content,
            "sha", sha,
            "branch", branchName))
        .retrieve()
        .bodyToMono(Void.class)
        .block();
  }

  private void createPr(String headBranch, String baseBranch, String title, String body) {
    try {
      Map<?, ?> response = webClient.post()
          .uri("/repos/" + repoName + "/pulls")
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + githubToken)
          .header(HttpHeaders.ACCEPT, "application/vnd.github.v3+json")
          .contentType(MediaType.APPLICATION_JSON)
          .bodyValue(Map.of(
              "title", title,
              "body", body,
              "head", headBranch,
              "base", baseBranch))
          .retrieve()
          .bodyToMono(Map.class)
          .block();

      if (response != null && response.containsKey("html_url")) {
        log.info("[GitHub API] PR 생성 성공: {}", response.get("html_url"));
      }
    } catch (Exception e) {
      log.error("[GitHub API] PR 생성 오류", e);
    }
  }

  /**
   * PR 번호로 Pull Request를 머지합니다.
   *
   * @param prNumber PR 번호
   * @return 머지 성공 여부
   */
  public boolean mergePullRequest(int prNumber) {
    if (githubToken.isBlank() || repoName.isBlank()) {
      log.warn("[GitHub] 인증 토큰 또는 저장소 정보가 설정되지 않아 PR 머지를 건너뜁니다.");
      return false;
    }

    try {
      webClient.put()
          .uri("/repos/" + repoName + "/pulls/" + prNumber + "/merge")
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + githubToken)
          .header(HttpHeaders.ACCEPT, "application/vnd.github.v3+json")
          .contentType(MediaType.APPLICATION_JSON)
          .bodyValue(Map.of("merge_method", "squash"))
          .retrieve()
          .bodyToMono(Map.class)
          .block();

      log.info("[GitHub API] PR #{} 머지 성공", prNumber);
      return true;
    } catch (Exception e) {
      log.error("[GitHub API] PR #{} 머지 실패", prNumber, e);
      return false;
    }
  }

  private String extractFilePath(String description) {
    if (description == null)
      return null;
    for (String line : description.lines().toList()) {
      if (line.toLowerCase().startsWith("패키지 경로") || line.toLowerCase().startsWith("file")) {
        String[] parts = line.split(":", 2);
        if (parts.length == 2) {
          // SnykCLI 출력: "com.example.package → my-file.jar" 등 일 수도 있으나,
          // 자바 파일 경로가 포함될 경우 정리 (우선은 Snyk CLI 출력에 실제 물리적 경로 정보가 완벽하지 않음)
          String path = parts[1].trim();
          // Snyk CLI 스캐너 상 "패키지 경로"가 pom.xml이나 build.gradle 같은 모듈을 가리킬 수 있음.
          // 하드코딩된 예제 파일 경로로 fallback 등 필요 가능
          if (path.contains("→") || path.contains("@")) {
            // Snyk 의존성 경로인 경우, 패치할 파일은 기본적으로 build.gradle.kts 또는 pom.xml 일 확률이 높음.
            // 우선 간단하게 build.gradle 로 가정
            return "build.gradle";
          }
          return path;
        }
      }
    }
    return "build.gradle"; // default fallback for dependencies
  }
}
