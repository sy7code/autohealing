package com.example.autohealing.dto;

import com.example.autohealing.entity.PluginConfig.AuthType;
import com.example.autohealing.entity.PluginConfig.PluginType;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ConfigDto {
  private Long id;
  private String name;
  private PluginType pluginType;
  private AuthType authType = AuthType.BEARER;
  private String authHeaderName;
  private String apiUrl;
  private String apiKey; // 사용자 입력 받거나 마스킹된 값을 반환
  private String httpMethod = "GET";
  private String resultJsonPath;
  private String titleField;
  private String severityField;
  private String severityMappingJson;
  private String idField;
  private String modelName;
  private boolean enabled = true;
}
