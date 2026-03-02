package com.example.autohealing.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.time.LocalDateTime;

/**
 * 전역 계층에서 통합된 예외 처리를 담당합니다.
 * 에러 정보는 SLF4J를 통해 서버에 남고 클라이언트에게는 통일된 ErrorResponse 규격이 응답됩니다.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(IllegalArgumentException.class)
  public ResponseEntity<ErrorResponse> handleIllegalArgumentException(
      IllegalArgumentException ex, HttpServletRequest request) {

    log.warn("❌ [Client Error] 400 Bad Request at {}: {}", request.getRequestURI(), ex.getMessage());
    return createErrorResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), request.getRequestURI());
  }

  @ExceptionHandler({ MissingServletRequestParameterException.class, MethodArgumentTypeMismatchException.class })
  public ResponseEntity<ErrorResponse> handleMissingParams(Exception ex, HttpServletRequest request) {

    log.warn("❌ [Client Error] 400 Bad Parameters at {}: {}", request.getRequestURI(), ex.getMessage());
    return createErrorResponse(HttpStatus.BAD_REQUEST, "Invalid or missing parameters", request.getRequestURI());
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ErrorResponse> handleGlobalException(Exception ex, HttpServletRequest request) {

    log.error("💥 [Server Error] 500 Internal Server Error at {}: ", request.getRequestURI(), ex);
    return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred",
        request.getRequestURI());
  }

  private ResponseEntity<ErrorResponse> createErrorResponse(HttpStatus status, String message, String path) {
    ErrorResponse errorResponse = ErrorResponse.builder()
        .timestamp(LocalDateTime.now())
        .status(status.value())
        .error(status.getReasonPhrase())
        .message(message)
        .path(path)
        .build();
    return new ResponseEntity<>(errorResponse, status);
  }
}
