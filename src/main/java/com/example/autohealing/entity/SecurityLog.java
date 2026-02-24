package com.example.autohealing.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

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

  /** 연동된 Jira 이슈 키 (예: SCRUM-66) */
  private String jiraKey;

  /** 생성된 GitHub PR 번호 */
  private Integer prNumber;

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
