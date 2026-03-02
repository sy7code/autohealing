package com.example.autohealing.exception;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 전역 에러 응답 객체 (표준화된 에러 리스폰스 템플릿)
 * 클라이언트나 클라우드 모니터링 시스템(Azure App Insights 등)이 통일된 규격으로 예외를 수집할 수 있도록 지원합니다.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ErrorResponse {

  private LocalDateTime timestamp;
  private int status;
  private String error;
  private String message;
  private String path;
}
