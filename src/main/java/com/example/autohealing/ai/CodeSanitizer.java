package com.example.autohealing.ai;

import org.springframework.stereotype.Component;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AI 모델이 출력한 결과물에서 순수 코드만 추출하기 위한 유틸리티 클래스.
 * 
 * v14 감사: 마크다운 코드 블록(```java ... ```)이 그대로 파일에 쓰여져
 * 문법 오류(Syntax Error)가 발생하는 현상을 방지합니다.
 */
@Component
public class CodeSanitizer {

  // 마크다운 블록 (```언어 ... ```) 안의 내용만 추출하는 정규식. 다중 줄 검사 포함.
  private static final Pattern MARKDOWN_CODE_BLOCK_PATTERN = Pattern.compile("```(?:[a-zA-Z]*)\\s*\\n(.*?)\\n```",
      Pattern.DOTALL);

  public String sanitize(String aiOutput) {
    if (aiOutput == null || aiOutput.isBlank()) {
      return aiOutput;
    }

    Matcher matcher = MARKDOWN_CODE_BLOCK_PATTERN.matcher(aiOutput);

    // 첫 번째 마크다운 블록을 찾아 추출. (일반적으로 가장 크고 올바른 코드 전체임)
    if (matcher.find()) {
      return matcher.group(1).trim();
    }

    // 블록 태그가 없는 경우 양쪽 끝 공백만 제거하여 원문 반환
    return aiOutput.trim();
  }
}
