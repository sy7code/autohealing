package com.example.autohealing.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "plugin_configs")
@Getter
@Setter
public class PluginConfig {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, unique = true)
  private String name;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private PluginType pluginType;

  @Enumerated(EnumType.STRING)
  private AuthType authType = AuthType.BEARER;

  private String authHeaderName;
  private String apiUrl;
  private String apiKeyEncrypted;
  private String httpMethod = "GET";
  private String resultJsonPath;
  private String titleField;
  private String severityField;
  private String severityMappingJson;
  private String idField;
  private String modelName;

  private boolean enabled = true;

  public enum PluginType {
    SCANNER, AI_ENGINE
  }

  public enum AuthType {
    BEARER, BASIC, HEADER, QUERY_PARAM
  }
}
