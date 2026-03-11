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

  /** 식별용 고유 취약점 ID (예: SNYK-xxx, SONAR-xxx) */
  private String vulnId;

  /** V13 추가: 실행된 스캐너 이름 */
  private String scannerName;

  /** V13 추가: 수정에 사용된 AI 엔진 이름 */
  private String aiEngineName;

  /** V13 추가: AI 처리 시간(ms) */
  private Long processingTimeMs;

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

  // v13 DB 방어 메서드 (Setter): 파일 전체를 DB에 밀어 넣으면 500MB 무료 DB가 터집니다.
  public void setOriginalCode(String code) {
    this.originalCode = code != null && code.length() > 5000
        ? code.substring(0, 5000) + "\n...[Truncated (Free DB Limit)]"
        : code;
  }

  public void setPatchedCode(String code) {
    this.patchedCode = code != null && code.length() > 5000
        ? code.substring(0, 5000) + "\n...[Truncated (Free DB Limit)]"
        : code;
  }

  // v9 방어: 에러 메시지(explanation) 저장 시 민감한 토큰 마스킹 처리
  public void setFixExplanation(String explanation) {
    if (explanation == null) {
      this.fixExplanation = null;
      return;
    }
    this.fixExplanation = explanation
        .replaceAll("(?i)(password|secret|token|api[_-]?key)\\s*[=:]\\s*[\"']?[^\\s\"']+", "$1=***")
        .replaceAll("sk-[a-zA-Z0-9]{20,}", "sk-***")
        .replaceAll("ghp_[a-zA-Z0-9]{36}", "ghp_***")
        .replaceAll("Bearer\\s+[a-zA-Z0-9._\\-]+", "Bearer ***")
        .replaceAll("AIza[a-zA-Z0-9_\\-]{35}", "AIza***")
        .replaceAll("xox[bpoa]-[a-zA-Z0-9\\-]+", "xox***");
  }
}
