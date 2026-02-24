package com.example.autohealing.repository;

import com.example.autohealing.entity.SecurityLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SecurityLogRepository extends JpaRepository<SecurityLog, Long> {

  /** 총 발견 수 */
  long count();

  /** AI 자동 수정 건수 */
  long countByAiFixedTrue();

  /** 관리자 승인 건수 */
  long countByIsApprovedTrue();

  /** CRITICAL 건수 */
  long countBySeverityIgnoreCase(String severity);

  /** Jira Key로 조회 */
  Optional<SecurityLog> findByJiraKey(String jiraKey);

  /** Snyk ID로 조회 */
  Optional<SecurityLog> findBySnykId(String snykId);

  /** 최근 순 리스트 (최대 100건) */
  List<SecurityLog> findTop100ByOrderByDetectedAtDesc();
}
