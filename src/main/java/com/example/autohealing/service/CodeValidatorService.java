package com.example.autohealing.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

import com.example.autohealing.exception.SandboxValidationException;

@Slf4j
@Service
public class CodeValidatorService {

  private final SandboxValidator sandboxValidator;

  public CodeValidatorService(SandboxValidator sandboxValidator) {
    this.sandboxValidator = sandboxValidator;
  }

  /**
   * AI가 제안한 수정 코드가 문법적으로 유효한지(컴파일 가능한지) 검증합니다.
   *
   * @param code     검증할 실제 Java 소스 코드
   * @param fileName 소스 코드의 원본 파일 이름 (예: MyClass.java)
   * @return 컴파일 성공 시 null, 실패 시 컴파일 오류 메시지(String)를 반환합니다.
   */
  public String validateCode(String code, String fileName) {
    // 0. AST 기반 샌드박스 정책 위반 선제 검사
    try {
      sandboxValidator.validate(code);
    } catch (SandboxValidationException sandboxEx) {
      log.warn("[CodeValidator] 샌드박스 보안 정책 위반 감지: {}", sandboxEx.getMessage());
      return sandboxEx.getMessage();
    }

    Path tempDir = Paths.get("src", "main", "resources", "temp", UUID.randomUUID().toString());
    Path tempFile = null;

    try {
      // 1. 임시 디렉토리 및 파일 생성
      Files.createDirectories(tempDir);

      // 패키지 경로를 포함한 파일 이름 대비 (단순 파일명만 추출)
      String simpleFileName = new File(fileName).getName();
      // Windows 금지 문자(:, @, >, <, |, *, ?, ") 제거 및 .java 확장자 보장
      simpleFileName = simpleFileName.replaceAll("[:\\\\/*?\"<>|@>]", "_");
      if (!simpleFileName.endsWith(".java")) {
        simpleFileName = "AiValidation.java";
      }
      tempFile = tempDir.resolve(simpleFileName);

      Files.writeString(tempFile, code);
      log.info("[CodeValidator] 임시 파일 생성 완료: {}", tempFile.toAbsolutePath());

      // 2. javac 컴파일 실행
      // 현재 클래스패스를 가져옵니다.
      String classPath = System.getProperty("java.class.path");

      ProcessBuilder processBuilder = new ProcessBuilder(
          "javac",
          "-cp", classPath,
          tempFile.toAbsolutePath().toString());

      processBuilder.directory(tempDir.toFile());
      processBuilder.redirectErrorStream(true); // 에러 스트림을 표준 출력으로 병합

      Process process = processBuilder.start();

      // 컴파일 결과 읽기
      StringBuilder output = new StringBuilder();
      try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        String line;
        while ((line = reader.readLine()) != null) {
          output.append(line).append("\n");
        }
      }

      int exitCode = process.waitFor();

      if (exitCode == 0) {
        log.info("[CodeValidator] 코드 검증 성공: {}", simpleFileName);
        return null; // 성공 시 null 반환
      } else {
        log.warn("[CodeValidator] 코드 컴파일 실패 (exit code {}):\n{}", exitCode, output.toString());
        return output.toString().trim(); // 컴파일 에러 메시지 반환
      }

    } catch (Exception e) {
      log.error("[CodeValidator] 코드 검증 중 예기치 못한 오류 발생", e);
      return "검증 프로세스 실행 중 오류 발생: " + e.getMessage();
    } finally {
      // 3. Cleanup: 임시 파일 및 디렉토리 삭제
      cleanup(tempDir);
    }
  }

  private void cleanup(Path tempDir) {
    if (tempDir == null || !Files.exists(tempDir)) {
      return;
    }
    try {
      Files.walk(tempDir)
          .sorted(java.util.Comparator.reverseOrder())
          .map(Path::toFile)
          .forEach(File::delete);
      log.info("[CodeValidator] 임시 디렉토리 클린업 완료: {}", tempDir);
    } catch (IOException e) {
      log.error("[CodeValidator] 임시 디렉토리 클린업 실패: {}", tempDir, e);
    }
  }
}
