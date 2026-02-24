package com.example.autohealing.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * 보안 스캔 결과 및 AI 자동 치료 진행 상태를 저장하는 JPA 엔티티.
 *
 * <p>
 * 이 엔티티는 GitHub 웹훅 수신 시 생성되며,
 * Snyk 스캔 결과, AI 수정 내역(원본/수정 코드), 승인 상태, PR 및 Jira 연동 키를 모두 포함하여
 * 관리자 대시보드(Vercel)에 필요한 모든 정보를 제공합니다.
 */
@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "security_logs")
public class SecurityLog {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private String resourceName;

  @Column(nullable = false)
  private String threatType;

  @Column(nullable = false)
  private String severity;

  @Column(nullable = false)
  private String status;

  @CreationTimestamp
  @Column(updatable = false)
  private LocalDateTime detectedAt;

  // ── Dashboard / Approval용 추가 필드 ──

  /** Snyk 취약점 ID (예: SNYK-JAVA-COMNIMBUSDS-6247633) */
  private String snykId;

  /** 연동된 Jira 이슈 키 (예: SCRUM-66) */
  private String jiraKey;

  /** 생성된 GitHub PR 번호 */
  private Integer prNumber;

  /** AI 자동 수정 여부 */
  @Column(nullable = false)
  private boolean aiFixed = false;

  /** 승인 여부 */
  @Column(nullable = false, columnDefinition = "boolean default false", name = "is_approved")
  private boolean isApproved = false;

  /** 패치 적용 완료 시간 */
  private LocalDateTime resolvedAt;

  /** 원본 소스코드 (Diff 뷰어용) */
  @Column(columnDefinition = "TEXT")
  private String originalCode;

  /** 수정된 소스코드 (Diff 뷰어용) */
  @Column(columnDefinition = "TEXT")
  private String patchedCode;

  /** 리뷰용 AI 자동 수정 요약 사유 */
  @Column(columnDefinition = "TEXT")
  private String fixExplanation;

  public SecurityLog(String resourceName, String threatType, String severity, String status) {
    this.resourceName = resourceName;
    this.threatType = threatType;
    this.severity = severity;
    this.status = status;
  }
}
