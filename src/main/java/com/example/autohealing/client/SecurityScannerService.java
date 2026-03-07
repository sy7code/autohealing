package com.example.autohealing.client;

import java.util.List;
import java.util.Map;

/**
 * 다중 스캐너 지원을 위한 공통 인터페이스
 */
public interface SecurityScannerService {

  /**
   * @return 스캐너 제공자 이름 (예: "Snyk", "SonarQube", "Generic-GitLab")
   */
  String providerName();

  /**
   * @param repositoryUri 저장소 정보 (로컬 경로 또는 원격 URL)
   * @return 발견된 취약점 목록 (List of Maps, 표준화된 데이터 구조)
   */
  List<Map<String, Object>> scan(String repositoryUri);
}
