package com.example.autohealing.service;

import com.example.autohealing.entity.SecurityLog;
import com.example.autohealing.parser.dto.UnifiedIssue;
import com.example.autohealing.repository.SecurityLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

/**
 * 중복 취약점 감지 시 무한 PR/이슈 생성을 방지하고,
 * 해결(Resolved) 후 다시 발생한 회귀(Regression) 취약점을 식별하는 서비스.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DeduplicationService {

  private final SecurityLogRepository repository;

  /**
   * 취약점 중복 여부 확인 및 PR 어뷰징 루프 방어.
   *
   * @param issue 처리 대상 취약점
   * @return true 이면 스킵 (이미 진행중이거나 단기 방어), false 이면 처리 진행 (신규 또는 회귀)
   */
  public boolean shouldSkip(UnifiedIssue issue) {
    String vulnId = issue.getId();
    if (vulnId == null || vulnId.isBlank()) {
      return false;
    }

    Optional<SecurityLog> latestLogOpt = repository.findTopByVulnIdOrderByDetectedAtDesc(vulnId);

    if (latestLogOpt.isEmpty()) {
      return false; // 처음 발견된 취약점
    }

    SecurityLog latestLog = latestLogOpt.get();
    String status = latestLog.getStatus();

    // 1. 이미 해결된 경우 (Regression 체크)
    if ("Resolved".equalsIgnoreCase(status) || "APPROVED".equalsIgnoreCase(status)) {
      LocalDateTime resolvedAt = latestLog.getResolvedAt() != null ? latestLog.getResolvedAt()
          : latestLog.getDetectedAt();
      long daysSinceResolved = ChronoUnit.DAYS.between(resolvedAt, LocalDateTime.now());

      if (daysSinceResolved > 7) {
        log.warn("[Deduplication] 과거에 해결된 취약점({})이 다시 감지되었습니다. (Regression). 재처리합니다.", vulnId);
        return false; // 7일 이상 지났으면 Regression으로 간주하여 새로 처리
      } else {
        log.info("[Deduplication] 최근 7일 내 해결된 취약점({})입니다. (오탐/브랜치 딜레이). 보호 차원에서 스킵합니다.", vulnId);
        return true;
      }
    }

    // 2. 오류로 인해 의도적으로 스킵 또는 차단된 이력
    if ("SKIPPED_TOO_LARGE".equals(status) || "BLOCKED_SENSITIVE_DATA".equals(status)) {
      long daysSinceDetected = ChronoUnit.DAYS.between(latestLog.getDetectedAt(), LocalDateTime.now());
      if (daysSinceDetected < 3) {
        log.info("[Deduplication] 파일 크기 제한/민감 정보 등으로 최근 차단된 취약점({})입니다. 단기 재시도를 방지합니다.", vulnId);
        return true;
      } else {
        return false; // 3일 지났으면 상황이 달라졌을 수 있으니 재시도 허용
      }
    }

    // 3. 그 외 상태 (AI 패치 대기중, 수동 리뷰 필요, 에러 등 처리 진행 중인 상태)
    log.info("[Deduplication] 현재 작업 중이거나 리뷰 대기 중인 취약점({})입니다. (상태: {}). 중복 파이프라인 진행을 차단합니다.", vulnId, status);
    return true;
  }
}
