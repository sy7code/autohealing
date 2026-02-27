package com.example.autohealing.service;

import com.example.autohealing.exception.SandboxValidationException;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.ImportDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;

/**
 * 실무/프로덕션 환경을 고려한 최상위 보안 샌드박스 검사기입니다.
 * JavaParser(AST)를 통해 AI 응답 코드를 파싱하고, 철저한 White-list(허용 목록) 기반으로
 * 안전하지 않은 임포트 파일이나 악의적인 메서드 호출을 사전에 차단합니다.
 */
@Slf4j
@Service
public class SandboxValidator {

  // 허용할 안전한 최상위 패키지 접두사 (Whitelist)
  private static final Set<String> ALLOWED_IMPORT_PREFIXES = Set.of(
      "java.lang",
      "java.util",
      "java.time",
      "java.math",
      "java.text",
      "org.springframework",
      "org.slf4j",
      "lombok",
      "javax.annotation",
      "jakarta.annotation",
      "javax.validation",
      "jakarta.validation",
      "com.example.autohealing" // 내 프로젝트 패키지도 허용
  );

  // 화이트리스트 패키지라 하더라도 명시적으로 차단할 악성 의심 클래스/패키지 (Blacklist 보완)
  private static final Set<String> RESTRICTED_IMPORTS = Set.of(
      "java.lang.reflect",
      "java.lang.Runtime",
      "java.lang.Process",
      "java.lang.ProcessBuilder",
      "java.lang.Thread",
      "java.lang.System",
      "org.springframework.context.support.ClassPathXmlApplicationContext" // Remote Code Execution 빌미
  );

  // AST 노드 분석 중 직접적으로 차단할 인스턴스/정적 메서드 호출명 세트
  // ex) System.exit(0), Runtime.getRuntime().exec()
  private static final Set<String> RESTRICTED_METHOD_CALLS = Set.of(
      "exit", "exec", "halt", "load", "loadLibrary", "gc", "runFinalization", "freeMemory", "invoke");

  /**
   * 문자열 형태의 소스 코드를 AST로 파싱하여 샌드박스 정책 위반이 있는지 검사합니다.
   *
   * @param sourceCode 검증할 Java 소스 코드
   * @throws SandboxValidationException 보안 정책에 위배되는 코드가 발견된 경우 발생
   */
  public void validate(String sourceCode) {
    if (sourceCode == null || sourceCode.isBlank()) {
      return;
    }

    try {
      CompilationUnit cu = StaticJavaParser.parse(sourceCode);

      // 1. 임포트 구문(Imports) 타당성 검증 (Whitelist + 보완 Blacklist 적용)
      validateImports(cu);

      // 2. 위험한 메서드 호출 검증
      validateMethodCalls(cu);

      log.debug("[SandboxValidator] AST 기반 보안 샌드박스 검사 통과 (안전한 코드)");

    } catch (com.github.javaparser.ParseProblemException e) {
      log.warn("[SandboxValidator] 코드 파싱 실패(문법 오류 의심) - 기존 javac 검증으로 이관", e);
      // 문법 오류는 후속 javac 검증(CodeValidatorService)에서 처리하도록 여기서는 예외로 잡지 않습니다.
    }
  }

  private void validateImports(CompilationUnit cu) {
    List<ImportDeclaration> imports = cu.findAll(ImportDeclaration.class);

    for (ImportDeclaration importDecl : imports) {
      String importName = importDecl.getNameAsString();

      // 1) 보완적 블랙리스트 먼저 확인
      for (String restricted : RESTRICTED_IMPORTS) {
        if (importName.equals(restricted) || importName.startsWith(restricted + ".")) {
          throw new SandboxValidationException("보안 정책 위반: 허용되지 않은 악성 클래스/패키지가 임포트되었습니다 (" + importName + ")");
        }
      }

      // 2) 화이트리스트 기반 통과 여부 확인
      boolean isAllowed = false;
      for (String allowedPrefix : ALLOWED_IMPORT_PREFIXES) {
        if (importName.startsWith(allowedPrefix)) {
          isAllowed = true;
          break;
        }
      }

      if (!isAllowed) {
        throw new SandboxValidationException("보안 정책 위반: 화이트리스트에 없는 외부 패키지 임포트입니다 (" + importName + ")");
      }
    }
  }

  private void validateMethodCalls(CompilationUnit cu) {
    List<MethodCallExpr> methodCalls = cu.findAll(MethodCallExpr.class);

    for (MethodCallExpr methodCall : methodCalls) {
      String methodName = methodCall.getNameAsString();

      if (RESTRICTED_METHOD_CALLS.contains(methodName)) {
        // 특히 System.exit, Runtime.exec 등을 직접 겨냥.
        // 메서드명만으로 체크하므로 엄격한 편이나, 백엔드 로직 자동 수정 환경에서는 이게 안전합니다.
        throw new SandboxValidationException("보안 정책 위반: 시스템에 치명적이거나 악용될 수 있는 메서드 호출 감지 (" + methodName + ")");
      }
    }
  }
}
