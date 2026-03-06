package com.example.autohealing.service;

import com.example.autohealing.parser.dto.UnifiedIssue;
import lombok.extern.slf4j.Slf4j;
import org.kohsuke.github.GHBranch;
import org.kohsuke.github.GHCheckRun;
import org.kohsuke.github.GHContent;
import org.kohsuke.github.GHPullRequest;
import org.kohsuke.github.GHRef;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;
import org.kohsuke.github.HttpException;
import org.kohsuke.github.PagedIterable;
import com.example.autohealing.config.GithubConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;

/**
 * GitHub API SDK (org.kohsuke:github-api)와 연동하여 레포지토리 제어,
 * 브랜치 생성, 코드 커밋 및 Pull Request(PR) 관리를 수행하는 통합 서비스.
 * AI가 생성한 패치 코드를 프로젝트에 제안하고 CI 결과를 검증하는 데 사용됩니다.
 */
@Slf4j
@Service
public class GithubService {

  private final String repoName;
  private final String baseBranch; // 기본값 "develop" 또는 "feature/ai-remediation-engine"
  private final GithubConfig githubConfig;
  private GitHub github;

  public GithubService(
      @Value("${GITHUB_TOKEN:}") String githubToken,
      @Value("${GITHUB_REPO:}") String repoName,
      @Value("${GITHUB_BASE_BRANCH:develop}") String baseBranch,
      GithubConfig githubConfig) {
    this.repoName = repoName;
    this.baseBranch = baseBranch;
    this.githubConfig = githubConfig;
    try {
      if (!githubToken.isBlank()) {
        this.github = new GitHubBuilder().withOAuthToken(githubToken).build();
      } else {
        log.warn("[GitHub] GITHUB_TOKEN이 설정되지 않았습니다.");
      }
    } catch (IOException e) {
      log.error("[GitHub] GitHub Client 초기화 에러", e);
    }
  }

  public String getRepoName() {
    return this.repoName;
  }

  /**
   * AI 코드가 적용된 파일 내용을 바탕으로 새 브랜치에 커밋하고 Pull Request를 생성합니다.
   *
   * @param issue        취약점 이슈 정보
   * @param originalCode 원본 소스코드
   * @param fixedCode    수정된 소스코드
   * @param explanation  AI가 작성한 원인 및 수정 내역 (한국어 설명)
   * @return 생성된 PR 번호 (실패 시 null)
   */
  public Integer createPullRequest(UnifiedIssue issue, String originalCode, String fixedCode, String explanation) {
    if (github == null || repoName.isBlank()) {
      log.warn("[GitHub] 인증 토큰 또는 저장소 정보가 설정되지 않아 PR 생성을 건너뜁니다.");
      return null;
    }

    String filePath = extractFilePath(issue.getDescription());
    if (filePath == null) {
      log.warn("[GitHub] 티켓 내용에서 파일 경로를 추출할 수 없어 PR 생성을 건너뜁니다. ID={}", issue.getId());
      return null;
    }

    String safeIssueId = issue.getId().replaceAll("[^a-zA-Z0-9-]", "-");
    String newBranchName = "fix/auto-fix-" + safeIssueId;

    log.info("[GitHub] PR 생성 프로세스 시작 - branch={}, file={}", newBranchName, filePath);

    try {
      GHRepository repo = github.getRepository(repoName);

      // 1. Get base branch SHA
      GHBranch base = repo.getBranch(baseBranch);
      String baseSha = base.getSHA1();

      // 2. Create new branch
      try {
        repo.createRef("refs/heads/" + newBranchName, baseSha);
      } catch (HttpException e) {
        log.warn("[GitHub API] 브랜치 생성 실패 (이미 존재할 수도 있음): {}", e.getMessage());
      }

      // 3. Get existing file (to update)
      GHContent currentFile = null;
      try {
        currentFile = repo.getFileContent(filePath, newBranchName);
      } catch (IOException e) {
        log.warn("[GitHub API] 대상 파일({})을 찾을 수 없습니다. (새 파일로 생성 시도)", filePath);
      }

      // 4. Update or Create file with fixed code
      String commitMessage = githubConfig.getPr().getCommitPrefix() + issue.getTitle()
          + githubConfig.getPr().getCommitSuffix();
      if (currentFile != null) {
        currentFile.update(fixedCode, commitMessage, newBranchName);
      } else {
        repo.createContent()
            .path(filePath)
            .content(fixedCode)
            .message(commitMessage)
            .branch(newBranchName)
            .commit();
      }

      // 5. Create PR
      String prTitle = githubConfig.getPr().getTitlePrefix() + " " + issue.getTitle();
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

      GHPullRequest pr = repo.createPullRequest(prTitle, newBranchName, baseBranch, prBody);
      log.info("[GitHub API] PR 생성 완료! - url: {}", pr.getHtmlUrl());

      return pr.getNumber();

    } catch (Exception e) {
      log.error("[GitHub API] PR 생성 과정 중 예외 발생", e);
      return null;
    }
  }

  /**
   * PR 의 Check Runs(또는 Status)를 조회하여 빌드/테스트 성공 여부를 확인합니다.
   *
   * @param prNumber PR 번호
   * @return 모두 성공(success)이면 true, 아니면 false
   */
  public boolean isPrTestsSuccessful(int prNumber) {
    if (github == null || repoName.isBlank()) {
      log.warn("[GitHub] 인증 토큰이나 저장소가 설정되지 않아 CI 검증을 무조건 통과처리 합니다.");
      return true;
    }
    try {
      GHRepository repo = github.getRepository(repoName);
      GHPullRequest pr = repo.getPullRequest(prNumber);
      String headSha = pr.getHead().getSha();

      // Check Runs API 확인
      PagedIterable<GHCheckRun> checkRuns = repo.getCommit(headSha).getCheckRuns();
      List<GHCheckRun> runList = checkRuns.toList();

      if (runList.isEmpty()) {
        log.info("[GitHub API] PR #{}에 등록된 Check Run이 없습니다. (CI 통과 간주)", prNumber);
        return true;
      }

      boolean allSuccess = true;
      for (GHCheckRun run : runList) {
        GHCheckRun.Status status = run.getStatus();
        GHCheckRun.Conclusion conclusion = run.getConclusion();

        log.info("[GitHub API] PR #{} Check Run '{}' 상태: status={}, conclusion={}",
            prNumber, run.getName(), status, conclusion);

        if (status != GHCheckRun.Status.COMPLETED) {
          log.warn("[GitHub API] PR #{} 검증 진행 중... ({})", prNumber, run.getName());
          allSuccess = false;
        } else if (conclusion != GHCheckRun.Conclusion.SUCCESS && conclusion != GHCheckRun.Conclusion.SKIPPED
            && conclusion != GHCheckRun.Conclusion.NEUTRAL) {
          log.warn("[GitHub API] PR #{} 검증 실패! ({}: conclusion={})", prNumber, run.getName(), conclusion);
          allSuccess = false;
        }
      }

      return allSuccess;

    } catch (IOException e) {
      log.error("[GitHub API] PR #{} 상태 확인 중 오류 발생", prNumber, e);
      return false;
    }
  }

  /**
   * PR 번호로 Pull Request를 머지하고 브랜치를 삭제합니다.
   *
   * @param prNumber PR 번호
   * @return 머지 성공 여부
   */
  public boolean mergePullRequest(int prNumber) {
    if (github == null || repoName.isBlank()) {
      log.warn("[GitHub] 인증 토큰 또는 저장소 정보가 없어 머지를 건너뜁니다.");
      return false;
    }

    try {
      GHRepository repo = github.getRepository(repoName);
      GHPullRequest pr = repo.getPullRequest(prNumber);

      pr.merge(githubConfig.getPr().getMergeMessage(), null, GHPullRequest.MergeMethod.SQUASH);
      log.info("[GitHub API] PR #{} 머지 성공", prNumber);

      // 브랜치 삭제
      String headRef = pr.getHead().getRef();
      GHBranch headBranch = repo.getBranch(headRef);
      if (headBranch != null && headRef.startsWith("fix/")) {
        GHRef ref = repo.getRef("heads/" + headRef);
        ref.delete();
        log.info("[GitHub API] 브랜치 {} 삭제 완료", headRef);
      }

      return true;
    } catch (IOException e) {
      log.error("[GitHub API] PR #{} 머지 또는 브랜치 삭제 실패", prNumber, e);
      return false;
    }
  }

  /**
   * GitHub에서 특정 파일의 내용을 읽어와 문자열로 반환합니다.
   *
   * @param filePath 파일 경로
   * @param branch   브랜치 이름 (null 이면 기본 브랜치 사용)
   * @return 파일 내용 문자열 (실패 시 null)
   */
  public String getFileContentAsString(String filePath, String branch) {
    if (github == null || repoName.isBlank())
      return null;
    String targetBranch = (branch != null) ? branch : baseBranch;
    try {
      GHRepository repo = github.getRepository(repoName);
      GHContent content = repo.getFileContent(filePath, targetBranch);
      try (java.io.InputStream is = content.read()) {
        return new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
      }
    } catch (Exception e) {
      log.warn("[GitHub API] 파일 내용 읽기 실패: {} (branch: {})", filePath, targetBranch);
      return null;
    }
  }

  private String extractFilePath(String description) {
    if (description == null)
      return null;
    for (String line : description.lines().toList()) {
      if (line.toLowerCase().startsWith("패키지 경로") || line.toLowerCase().startsWith("file")) {
        String[] parts = line.split(":", 2);
        if (parts.length == 2) {
          String path = parts[1].trim();
          if (path.contains("→") || path.contains("@")) {
            return "build.gradle";
          }
          return path;
        }
      }
    }
    return "build.gradle";
  }
}
