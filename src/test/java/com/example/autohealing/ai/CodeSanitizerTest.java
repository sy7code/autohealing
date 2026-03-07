package com.example.autohealing.ai;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CodeSanitizerTest {

  private final CodeSanitizer sanitizer = new CodeSanitizer();

  @Test
  @DisplayName("일반 자바 마크다운 블록 제거 테스트")
  void testSanitizeJavaMarkdown() {
    String aiOutput = "여기 수정된 코드가 있습니다.\n\n```java\npublic class Test {\n    // Code here\n}\n```\n잘 쓰세요.";
    String result = sanitizer.sanitize(aiOutput);
    assertThat(result).isEqualTo("public class Test {\n    // Code here\n}");
  }

  @Test
  @DisplayName("언어 지정 없는 마크다운 블록 제거 테스트")
  void testSanitizePlainMarkdown() {
    String aiOutput = "```\nSystem.out.println(\"Hello\");\n```";
    String result = sanitizer.sanitize(aiOutput);
    assertThat(result).isEqualTo("System.out.println(\"Hello\");");
  }

  @Test
  @DisplayName("마크다운 블록이 없는 경우 원문 반환 테스트")
  void testSanitizeNoMarkdown() {
    String aiOutput = "public class PureCode { }";
    String result = sanitizer.sanitize(aiOutput);
    assertThat(result).isEqualTo("public class PureCode { }");
  }

  @Test
  @DisplayName("다중 마크다운 블록이 있을 경우 첫 번째 블록 반환")
  void testMultipleMarkdownBlocks() {
    String aiOutput = "```java\nString a = \"first\";\n```\n그리고 예제 2:\n```\nString b = \"second\";\n```";
    String result = sanitizer.sanitize(aiOutput);
    assertThat(result).isEqualTo("String a = \"first\";");
  }
}
