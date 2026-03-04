package com.example.autohealing.exception;

/**
 * AI가 제안한 소스 코드에서 허용되지 않은 보안 정책 위반(예: 비인가 패키지 임포트, 악의적 메서드 호출)이
 * 발견될 때 발생하는 샌드박스 검증 예외입니다.
 */
public class SandboxValidationException extends RuntimeException {

  public SandboxValidationException(String message) {
    super(message);
  }

  public SandboxValidationException(String message, Throwable cause) {
    super(message, cause);
  }
}
