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
