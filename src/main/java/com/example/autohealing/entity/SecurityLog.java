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

  /** Snyk 취약점 ID (예: SNYK-JAVA-COMNIMBUSDS-6247633) */
  private String snykId;

  /** 연동된 Jira 이슈 키 (예: SCRUM-66) */
  private String jiraKey;

  /** 생성된 GitHub PR 번호 */
  private Integer prNumber;

  /** AI 자동 수정 여부 */
  @Column(nullable = false)
  private boolean aiFixed = false;

  /** 관리자 승인 여부 */
  @Column(nullable = false)
  private boolean approved = false;

  /** AI가 생성한 수정 코드 설명 */
  @Column(columnDefinition = "TEXT")
  private String fixExplanation;

  public SecurityLog(String resourceName, String threatType, String severity, String status) {
    this.resourceName = resourceName;
    this.threatType = threatType;
    this.severity = severity;
    this.status = status;
  }
}
