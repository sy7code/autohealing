package com.example.autohealing.common;

/**
 * 스캐너 및 보안 이슈 처리에 사용되는 공통 상수 모음.
 * 하드코딩된 문자열을 중앙화하여 오타 및 분산 관리 문제를 방지합니다.
 */
public final class ScannerConstants {

  private ScannerConstants() {
  }

  /** Snyk 코드 스캐너 출처 식별자 */
  public static final String SOURCE_SNYK = "SNYK";

  /** Azure 인프라 스캐너(CSPM) 출처 식별자 */
  public static final String SOURCE_AZURE_CSPM = "Azure-CSPM";

  /** AI 수정 코드에 민감 정보가 탐지되어 PR 생성이 차단된 상태 */
  public static final String STATUS_BLOCKED_SENSITIVE_DATA = "BLOCKED_SENSITIVE_DATA";

  /** 파일 경로 불일치로 AI 수정이 생략된 상태 */
  public static final String STATUS_SKIPPED_FILE_NOT_FOUND = "SKIPPED_FILE_NOT_FOUND";

  /** 파일이 너무 커서 AI 수정이 생략된 상태 */
  public static final String STATUS_SKIPPED_TOO_LARGE = "SKIPPED_TOO_LARGE";

  /** 인프라 취약점 감지 상태 (수동 리뷰 필요) */
  public static final String STATUS_DETECTED = "Detected";
}
