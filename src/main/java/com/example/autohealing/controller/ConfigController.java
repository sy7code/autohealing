package com.example.autohealing.controller;

import com.example.autohealing.dto.ConfigDto;
import com.example.autohealing.entity.PluginConfig;
import com.example.autohealing.repository.PluginConfigRepository;
import com.example.autohealing.service.EncryptionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 스캐너 플러그인과 AI 엔진을 동적으로 등록, 조회, 수정, 삭제하는 REST 컨트롤러.
 * 프론트엔드의 /settings 페이지에서 호출합니다.
 */
@Slf4j
@RestController
@RequestMapping("/api/config")
@RequiredArgsConstructor
public class ConfigController {

  private final PluginConfigRepository pluginConfigRepository;
  private final EncryptionService encryptionService;
  private final org.springframework.web.client.RestTemplate restTemplate;

  // ─────────────────────────────────────────────────────────────────────────
  // Scanners
  // ─────────────────────────────────────────────────────────────────────────

  @GetMapping("/scanners")
  public ResponseEntity<List<ConfigDto>> getScanners() {
    return getConfigsByType(PluginConfig.PluginType.SCANNER);
  }

  @PostMapping("/scanners")
  public ResponseEntity<ConfigDto> createScanner(@RequestBody ConfigDto dto) {
    dto.setPluginType(PluginConfig.PluginType.SCANNER);
    return createConfig(dto);
  }

  @PutMapping("/scanners/{id}")
  public ResponseEntity<ConfigDto> updateScanner(@PathVariable Long id, @RequestBody ConfigDto dto) {
    dto.setPluginType(PluginConfig.PluginType.SCANNER);
    return updateConfig(id, dto);
  }

  @DeleteMapping("/scanners/{id}")
  public ResponseEntity<Void> deleteScanner(@PathVariable Long id) {
    return deleteConfig(id, PluginConfig.PluginType.SCANNER);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // AI Engines
  // ─────────────────────────────────────────────────────────────────────────

  @GetMapping("/ai-engines")
  public ResponseEntity<List<ConfigDto>> getAiEngines() {
    return getConfigsByType(PluginConfig.PluginType.AI_ENGINE);
  }

  @PostMapping("/ai-engines")
  public ResponseEntity<ConfigDto> createAiEngine(@RequestBody ConfigDto dto) {
    dto.setPluginType(PluginConfig.PluginType.AI_ENGINE);
    return createConfig(dto);
  }

  @PutMapping("/ai-engines/{id}")
  public ResponseEntity<ConfigDto> updateAiEngine(@PathVariable Long id, @RequestBody ConfigDto dto) {
    dto.setPluginType(PluginConfig.PluginType.AI_ENGINE);
    return updateConfig(id, dto);
  }

  @DeleteMapping("/ai-engines/{id}")
  public ResponseEntity<Void> deleteAiEngine(@PathVariable Long id) {
    return deleteConfig(id, PluginConfig.PluginType.AI_ENGINE);
  }

  @PostMapping("/test")
  public ResponseEntity<java.util.Map<String, Object>> testConnection(@RequestBody ConfigDto dto) {
    log.info("📡 [ConfigController] 연동 테스트 시작: {} (type={})", dto.getName(), dto.getPluginType());
    java.util.Map<String, Object> result = new java.util.HashMap<>();

    try {
      String apiKey = dto.getApiKey();
      // 만약 마스킹된 키가 넘어왔고 ID가 있다면 DB에서 실제 키를 가져와 복호화함
      if (apiKey != null && apiKey.contains("****") && dto.getId() != null) {
        apiKey = pluginConfigRepository.findById(dto.getId())
            .map(PluginConfig::getApiKeyEncrypted)
            .map(encryptionService::decrypt)
            .orElse("");
      }

      if (dto.getPluginType() == PluginConfig.PluginType.SCANNER) {
        return testScannerConnection(dto, apiKey);
      } else if (dto.getPluginType() == PluginConfig.PluginType.AI_ENGINE) {
        return testAiConnection(dto, apiKey);
      }

      result.put("success", false);
      result.put("message", "알 수 없는 플러그인 타입입니다.");
      return ResponseEntity.badRequest().body(result);

    } catch (Exception e) {
      log.error("💥 [ConfigController] 연동 테스트 중 에러: ", e);
      result.put("success", false);
      result.put("message", "오류 발생: " + e.getMessage());
      return ResponseEntity.status(500).body(result);
    }
  }

  private ResponseEntity<java.util.Map<String, Object>> testScannerConnection(ConfigDto dto, String apiKey) {
    java.util.Map<String, Object> result = new java.util.HashMap<>();
    try {
      org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
      if (apiKey != null && !apiKey.isBlank()) {
        if (dto.getAuthType() == PluginConfig.AuthType.BEARER) {
          headers.setBearerAuth(apiKey);
        } else if (dto.getAuthType() == PluginConfig.AuthType.HEADER) {
          headers.set(dto.getAuthHeaderName() != null ? dto.getAuthHeaderName() : "Authorization", apiKey);
        } else if (dto.getAuthType() == PluginConfig.AuthType.BASIC) {
          headers.setBasicAuth("", apiKey);
        }
      }

      org.springframework.http.HttpEntity<Void> entity = new org.springframework.http.HttpEntity<>(headers);
      org.springframework.http.HttpMethod method = dto.getHttpMethod() != null
          ? org.springframework.http.HttpMethod.valueOf(dto.getHttpMethod())
          : org.springframework.http.HttpMethod.GET;

      ResponseEntity<String> response = restTemplate.exchange(dto.getApiUrl(), method, entity, String.class);

      if (response.getStatusCode().is2xxSuccessful()) {
        result.put("success", true);
        result.put("message", "연동 성공! (상태 코드: " + response.getStatusCode() + ")");
        return ResponseEntity.ok(result);
      } else {
        result.put("success", false);
        result.put("message", "연동 실패 (상태 코드: " + response.getStatusCode() + ")");
        return ResponseEntity.ok(result);
      }
    } catch (Exception e) {
      result.put("success", false);
      result.put("message", "연결 실패: " + e.getMessage());
      return ResponseEntity.ok(result);
    }
  }

  private ResponseEntity<java.util.Map<String, Object>> testAiConnection(ConfigDto dto, String apiKey) {
    java.util.Map<String, Object> result = new java.util.HashMap<>();
    try {
      org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
      headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
      if (apiKey != null && !apiKey.isBlank()) {
        headers.setBearerAuth(apiKey);
      }

      java.util.Map<String, Object> requestBody = new java.util.HashMap<>();
      requestBody.put("model", dto.getModelName() != null ? dto.getModelName() : "gpt-4o");
      requestBody.put("messages", java.util.List.of(
          java.util.Map.of("role", "user", "content", "ping")));
      requestBody.put("max_tokens", 5);

      org.springframework.http.HttpEntity<java.util.Map<String, Object>> entity = new org.springframework.http.HttpEntity<>(
          requestBody, headers);
      ResponseEntity<java.util.Map> response = restTemplate.postForEntity(dto.getApiUrl(), entity, java.util.Map.class);

      if (response.getStatusCode().is2xxSuccessful()) {
        result.put("success", true);
        result.put("message", "AI 엔진 연동 성공!");
        return ResponseEntity.ok(result);
      } else {
        result.put("success", false);
        result.put("message", "AI 엔진 연동 실패 (상태 코드: " + response.getStatusCode() + ")");
        return ResponseEntity.ok(result);
      }
    } catch (Exception e) {
      result.put("success", false);
      result.put("message", "AI 연결 실패: " + e.getMessage());
      return ResponseEntity.ok(result);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Internal Helper Methods
  // ─────────────────────────────────────────────────────────────────────────

  private ResponseEntity<List<ConfigDto>> getConfigsByType(PluginConfig.PluginType type) {
    try {
      List<ConfigDto> dtos = pluginConfigRepository.findByPluginType(type).stream().map(config -> {
        ConfigDto dto = toDto(config);
        // v7 보안 요건: 조회 시 API 키 마스킹
        if (config.getApiKeyEncrypted() != null && !config.getApiKeyEncrypted().isBlank()) {
          String plain = encryptionService.decrypt(config.getApiKeyEncrypted());
          dto.setApiKey(encryptionService.mask(plain));
        }
        return dto;
      }).toList();
      return ResponseEntity.ok(dtos);
    } catch (Exception e) {
      log.error("💥 [ConfigController] 목록 조회 중 예외 발생 (type={}): ", type, e);
      return ResponseEntity.internalServerError().build();
    }
  }

  private ResponseEntity<ConfigDto> createConfig(ConfigDto dto) {
    // v7: name 중복 검사
    if (pluginConfigRepository.findByName(dto.getName()).isPresent()) {
      log.warn("이미 존재하는 플러그인 이름입니다: {}", dto.getName());
      return ResponseEntity.badRequest().build();
    }
    PluginConfig config = toEntity(dto, new PluginConfig());
    if (dto.getApiKey() != null && !dto.getApiKey().isBlank()) {
      config.setApiKeyEncrypted(encryptionService.encrypt(dto.getApiKey()));
    }
    PluginConfig saved = pluginConfigRepository.save(config);
    return ResponseEntity.ok(toDto(saved));
  }

  private ResponseEntity<ConfigDto> updateConfig(Long id, ConfigDto dto) {
    return pluginConfigRepository.findById(id).map(existing -> {
      // 이름이 변경되었는데 이미 존재하는 이름이라면 불가능
      if (!existing.getName().equals(dto.getName()) && pluginConfigRepository.findByName(dto.getName()).isPresent()) {
        log.warn("이미 존재하는 플러그인 이름으로 변경 시도: {}", dto.getName());
        return new org.springframework.http.ResponseEntity<ConfigDto>(org.springframework.http.HttpStatus.BAD_REQUEST);
      }
      PluginConfig config = toEntity(dto, existing);
      // v7: 키가 새로 넘어오고, 마스킹된 문자열이 아닐 때만 업데이트 (안그러면 이미 마스킹된 "****"가 암호화되어 저장됨)
      if (dto.getApiKey() != null && !dto.getApiKey().isBlank() && !dto.getApiKey().contains("****")) {
        config.setApiKeyEncrypted(encryptionService.encrypt(dto.getApiKey()));
      }
      PluginConfig saved = pluginConfigRepository.save(config);
      return ResponseEntity.ok(toDto(saved));
    }).orElseGet(() -> new org.springframework.http.ResponseEntity<>(org.springframework.http.HttpStatus.NOT_FOUND));
  }

  private ResponseEntity<Void> deleteConfig(Long id, PluginConfig.PluginType type) {
    return pluginConfigRepository.findById(id)
        .filter(c -> c.getPluginType() == type)
        .map(c -> {
          pluginConfigRepository.delete(c);
          return new org.springframework.http.ResponseEntity<Void>(org.springframework.http.HttpStatus.NO_CONTENT);
        })
        .orElseGet(() -> new org.springframework.http.ResponseEntity<>(org.springframework.http.HttpStatus.NOT_FOUND));
  }

  private ConfigDto toDto(PluginConfig entity) {
    if (entity == null) return null;
    ConfigDto dto = new ConfigDto();
    dto.setId(entity.getId());
    dto.setName(entity.getName());
    dto.setPluginType(entity.getPluginType());
    dto.setAuthType(entity.getAuthType());
    dto.setAuthHeaderName(entity.getAuthHeaderName());
    dto.setApiUrl(entity.getApiUrl());
    dto.setHttpMethod(entity.getHttpMethod() != null ? entity.getHttpMethod() : "GET");
    dto.setResultJsonPath(entity.getResultJsonPath());
    dto.setTitleField(entity.getTitleField());
    dto.setSeverityField(entity.getSeverityField());
    dto.setSeverityMappingJson(entity.getSeverityMappingJson());
    dto.setIdField(entity.getIdField());
    dto.setModelName(entity.getModelName());
    dto.setEnabled(entity.isEnabled());
    return dto;
  }

  private PluginConfig toEntity(ConfigDto dto, PluginConfig entity) {
    entity.setName(dto.getName());
    entity.setPluginType(dto.getPluginType());
    entity.setAuthType(dto.getAuthType());
    entity.setAuthHeaderName(dto.getAuthHeaderName());
    entity.setApiUrl(dto.getApiUrl());
    entity.setHttpMethod(dto.getHttpMethod());
    entity.setResultJsonPath(dto.getResultJsonPath());
    entity.setTitleField(dto.getTitleField());
    entity.setSeverityField(dto.getSeverityField());
    entity.setSeverityMappingJson(dto.getSeverityMappingJson());
    entity.setIdField(dto.getIdField());
    entity.setModelName(dto.getModelName());
    entity.setEnabled(dto.isEnabled());
    return entity;
  }
}
