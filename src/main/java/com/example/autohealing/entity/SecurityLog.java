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

  public SecurityLog(String resourceName, String threatType, String severity, String status) {
    this.resourceName = resourceName;
    this.threatType = threatType;
    this.severity = severity;
    this.status = status;
  }
}
