package com.example.autohealing.client;

import com.example.autohealing.parser.dto.UnifiedIssue;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Snyk CLI를 직접 실행해 보안 취약점을 스캔하는 서비스.
 *
 * <pre>
 * 실행 명령어: snyk test --json
 * </pre>
 *
 * <p>
 * REST API 플랜 제한 없이 로컬 프로젝트를 실시간 스캔합니다.
 * SNYK_TOKEN 환경변수(또는 {@code snyk auth} 인증)가 필요합니다.
 *
 * <p>
 * 스캔 대상 경로는 {@code LOCAL_REPO_PATH} 환경변수로 제어합니다.
 */
@Slf4j
@Service
public class SnykCliScannerService {

  private static final String SNYK_CMD = "snyk";

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Value("${LOCAL_REPO_PATH:}")
  private String defaultProjectPath;

  // ─────────────────────────────────────────────────────────────────────────
  // Public API
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * 지정된 프로젝트 경로에서 {@code snyk test --json}을 실행하고
   * 취약점 목록을 {@link UnifiedIssue} 리스트로 반환합니다.
   *
   * @param projectPath 스캔할 프로젝트 루트 경로. null이면 LOCAL_REPO_PATH 사용.
   * @return 파싱된 취약점 이슈 목록
   */
  public List<UnifiedIssue> scan(String projectPath) {
    String targetPath = resolveProjectPath(projectPath);
    if (targetPath == null) {
      log.error("[SnykCLI] 스캔 경로 미설정 - LOCAL_REPO_PATH 또는 파라미터를 지정하세요.");
      return Collections.emptyList();
    }

    log.info("[SnykCLI] 스캔 시작 - path={}", targetPath);

    try {
      String jsonOutput = runSnykTest(targetPath);
      if (jsonOutput == null || jsonOutput.isBlank()) {
        log.warn("[SnykCLI] 출력 없음");
        return Collections.emptyList();
      }
      return parseSnykJson(jsonOutput);

    } catch (SnykNotInstalledException e) {
      log.error("[SnykCLI] Snyk CLI 미설치 - npm install snyk -g 를 실행하세요.");
      return Collections.emptyList();
    } catch (SnykAuthException e) {
      log.error("[SnykCLI] 인증 실패 - snyk auth 또는 SNYK_TOKEN 환경변수를 설정하세요.");
      return Collections.emptyList();
    } catch (Exception e) {
      log.error("[SnykCLI] 스캔 오류", e);
      return Collections.emptyList();
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – CLI 실행
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * {@code snyk test --json}을 실행하고 stdout을 반환합니다.
   *
   * @return JSON 문자열 (취약점이 없으면 빈 JSON, 오류 시 null)
   */
  private String runSnykTest(String projectPath) throws Exception {
    // Windows/Linux 모두 호환되도록 ProcessBuilder 사용
    boolean isWindows = System.getProperty("os.name").toLowerCase().contains("win");
    List<String> command = isWindows
        ? List.of("cmd.exe", "/c", SNYK_CMD, "test", "--json", "--all-projects")
        : List.of(SNYK_CMD, "test", "--json", "--all-projects");

    ProcessBuilder pb = new ProcessBuilder(command);
    pb.directory(new File(projectPath));
    pb.redirectErrorStream(false); // stderr는 별도 읽기
    pb.environment().put("CI", "true"); // 인터랙티브 프롬프트 방지

    Process tmpProcess = null;
    try {
      tmpProcess = pb.start();
      final Process process = tmpProcess;

      // stdout (JSON 결과)
      StringBuilder stdout = new StringBuilder();
      // stderr (오류 메시지)
      StringBuilder stderr = new StringBuilder();

      Thread stdoutThread = new Thread(() -> {
        try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
          String line;
          while ((line = reader.readLine()) != null) {
            stdout.append(line).append("\n");
          }
        } catch (Exception ignored) {
        }
      });

      Thread stderrThread = new Thread(() -> {
        try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
          String line;
          while ((line = reader.readLine()) != null) {
            stderr.append(line).append("\n");
          }
        } catch (Exception ignored) {
        }
      });

      stdoutThread.start();
      stderrThread.start();

      // 타임아웃 3분 설정 (Security Scanner 특성 상 오래 걸릴 수 있으나 무한대기 방지)
      boolean finished = process.waitFor(3, TimeUnit.MINUTES);
      if (!finished) {
        log.error("[SnykCLI] 프로세스 실행 시간이 초과되었습니다 (3분).");
        process.destroyForcibly();
        return null;
      }

      int exitCode = process.exitValue();
      stdoutThread.join(5000);
      stderrThread.join(5000);

      String stderrStr = stderr.toString();
      log.debug("[SnykCLI] exitCode={}, stderr={}", exitCode, stderrStr);

      // exitCode: 0=OK, 1=취약점 발견, 2=실패, 3=미지원
      if (exitCode == 2 || exitCode == 3) {
        if (stderrStr.contains("MissingApiTokenError") || stderrStr.contains("Authentication")) {
          throw new SnykAuthException("Snyk 인증 실패");
        }
        log.error("[SnykCLI] 스캔 실패 - exitCode={}, stderr={}", exitCode, stderrStr);
        return null;
      }

      // exitCode 0(정상) 또는 1(취약점 발견) 모두 JSON 출력 파싱
      return stdout.toString();
    } catch (Exception e) {
      if (e.getMessage() != null && e.getMessage().contains("cannot run program")) {
        throw new SnykNotInstalledException("snyk 명령어를 찾을 수 없습니다.");
      }
      throw e;
    } finally {
      if (tmpProcess != null && tmpProcess.isAlive()) {
        tmpProcess.destroyForcibly();
      }
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – JSON 파싱
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * {@code snyk test --json} 출력을 {@link UnifiedIssue} 목록으로 변환합니다.
   *
   * <p>
   * 단일 프로젝트: {@code { "vulnerabilities": [...] }}
   * <p>
   * 멀티 프로젝트: {@code [{ "vulnerabilities": [...] }, ...]}
   */
  private List<UnifiedIssue> parseSnykJson(String json) {
    List<UnifiedIssue> result = new ArrayList<>();
    try {
      JsonNode root = objectMapper.readTree(json);

      if (root.isArray()) {
        // --all-projects 결과는 배열
        for (JsonNode projectNode : root) {
          result.addAll(extractVulnerabilities(projectNode));
        }
      } else {
        result.addAll(extractVulnerabilities(root));
      }

    } catch (Exception e) {
      log.error("[SnykCLI] JSON 파싱 실패 - json={}", json.substring(0, Math.min(200, json.length())), e);
    }

    log.info("[SnykCLI] 파싱 완료 - {}건", result.size());
    return result;
  }

  private List<UnifiedIssue> extractVulnerabilities(JsonNode projectNode) {
    List<UnifiedIssue> issues = new ArrayList<>();
    JsonNode vulns = projectNode.path("vulnerabilities");
    if (!vulns.isArray())
      return issues;

    for (JsonNode vuln : vulns) {
      try {
        String id = vuln.path("id").asText("unknown");
        String title = vuln.path("title").asText("No title");
        String severity = vuln.path("severity").asText("medium");

        // 패키지 경로: from[] 배열
        String fromPath = "";
        JsonNode fromArr = vuln.path("from");
        if (fromArr.isArray() && !fromArr.isEmpty()) {
          List<String> parts = new ArrayList<>();
          fromArr.forEach(n -> parts.add(n.asText()));
          fromPath = String.join(" → ", parts);
        }

        // 해결 버전: fixedIn[]
        String fixedIn = "";
        JsonNode fixedArr = vuln.path("fixedIn");
        if (fixedArr.isArray() && !fixedArr.isEmpty()) {
          fixedIn = fixedArr.get(0).asText();
        }

        String description = buildDescription(vuln, fromPath, fixedIn);

        UnifiedIssue issue = UnifiedIssue.builder()
            .id(id)
            .source("SNYK_CLI")
            .title(String.format("[Snyk][%s] %s", severity.toUpperCase(), title))
            .description(description)
            .severity(mapSeverity(severity))
            .build();

        issues.add(issue);
        log.debug("[SnykCLI] 이슈 파싱: id={}, severity={}", id, severity);

      } catch (Exception e) {
        log.warn("[SnykCLI] 개별 취약점 파싱 실패: {}", e.getMessage());
      }
    }
    return issues;
  }

  private String buildDescription(JsonNode vuln, String fromPath, String fixedIn) {
    return String.format("""
        취약점 ID  : %s
        패키지 경로 : %s
        해결 버전   : %s
        상세 내용   : %s
        CVE         : %s
        """,
        vuln.path("id").asText("-"),
        fromPath.isBlank() ? "-" : fromPath,
        fixedIn.isBlank() ? "패치 없음" : fixedIn,
        vuln.path("description").asText("-"),
        vuln.path("identifiers").path("CVE").toString());
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Private – 유틸
  // ─────────────────────────────────────────────────────────────────────────

  private String resolveProjectPath(String projectPath) {
    if (projectPath != null && !projectPath.isBlank())
      return projectPath;
    if (defaultProjectPath != null && !defaultProjectPath.isBlank())
      return defaultProjectPath;
    return null;
  }

  private UnifiedIssue.SeverityLevel mapSeverity(String raw) {
    return switch (raw.toLowerCase()) {
      case "critical" -> UnifiedIssue.SeverityLevel.CRITICAL;
      case "high" -> UnifiedIssue.SeverityLevel.HIGH;
      case "medium" -> UnifiedIssue.SeverityLevel.MEDIUM;
      case "low" -> UnifiedIssue.SeverityLevel.LOW;
      default -> UnifiedIssue.SeverityLevel.INFO;
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 예외 클래스
  // ─────────────────────────────────────────────────────────────────────────

  public static class SnykNotInstalledException extends RuntimeException {
    public SnykNotInstalledException(String msg) {
      super(msg);
    }
  }

  public static class SnykAuthException extends RuntimeException {
    public SnykAuthException(String msg) {
      super(msg);
    }
  }
}
