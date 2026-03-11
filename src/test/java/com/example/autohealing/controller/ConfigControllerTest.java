package com.example.autohealing.controller;

import com.example.autohealing.dto.ConfigDto;
import com.example.autohealing.entity.PluginConfig;
import com.example.autohealing.repository.PluginConfigRepository;
import com.example.autohealing.service.EncryptionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(ConfigController.class)
@org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc(addFilters = false)
class ConfigControllerTest {

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  private ObjectMapper objectMapper;

  @MockBean
  private PluginConfigRepository pluginConfigRepository;

  @MockBean
  private EncryptionService encryptionService;

  @MockBean
  private com.example.autohealing.config.security.JwtProvider jwtProvider;

  @MockBean
  private org.springframework.web.client.RestTemplate restTemplate;

  @Test
  @DisplayName("스캐너 목록 조회 시 API Key가 마스킹되어 반환된다")
  void getScanners_masksApiKey() throws Exception {
    PluginConfig config = new PluginConfig();
    config.setId(1L);
    config.setName("Snyk API");
    config.setPluginType(PluginConfig.PluginType.SCANNER);
    config.setApiKeyEncrypted("encrypted_val");

    Mockito.when(pluginConfigRepository.findByPluginType(PluginConfig.PluginType.SCANNER))
        .thenReturn(List.of(config));
    Mockito.when(encryptionService.decrypt("encrypted_val")).thenReturn("plain_secret");
    Mockito.when(encryptionService.mask("plain_secret")).thenReturn("plai****cret");

    mockMvc.perform(get("/api/config/scanners"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].name").value("Snyk API"))
        .andExpect(jsonPath("$[0].apiKey").value("plai****cret"));
  }

  @Test
  @DisplayName("새 스캐너 추가 시 이름이 중복되면 400 Bad Request 리턴")
  void createScanner_duplicateName_returnsBadRequest() throws Exception {
    ConfigDto dto = new ConfigDto();
    dto.setName("DuplicateScanner");

    Mockito.when(pluginConfigRepository.findByName("DuplicateScanner"))
        .thenReturn(Optional.of(new PluginConfig()));

    mockMvc.perform(post("/api/config/scanners")
        .contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(dto)))
        .andExpect(status().isBadRequest());
  }

  @Test
  @DisplayName("새 AI 엔진 추가 후 평문 키가 암호화되어 저장된다")
  void createAiEngine_encryptsApiKey() throws Exception {
    ConfigDto dto = new ConfigDto();
    dto.setName("OpenAI");
    dto.setApiKey("my_plain_key");

    Mockito.when(pluginConfigRepository.findByName("OpenAI")).thenReturn(Optional.empty());
    Mockito.when(encryptionService.encrypt("my_plain_key")).thenReturn("enc_key");

    PluginConfig savedConfig = new PluginConfig();
    savedConfig.setId(2L);
    savedConfig.setName("OpenAI");
    savedConfig.setPluginType(PluginConfig.PluginType.AI_ENGINE);

    Mockito.when(pluginConfigRepository.save(any(PluginConfig.class))).thenReturn(savedConfig);

    mockMvc.perform(post("/api/config/ai-engines")
        .contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(dto)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.id").value(2))
        .andExpect(jsonPath("$.name").value("OpenAI"));

    Mockito.verify(encryptionService).encrypt("my_plain_key");
    Mockito.verify(pluginConfigRepository).save(Mockito.argThat(c -> c.getApiKeyEncrypted().equals("enc_key")));
  }

  @Test
  @DisplayName("스캐너 수정 시 마스킹된 문자열(****)이 오면 키를 업데이트하지 않는다")
  void updateScanner_withMaskedKey_skipsEncryption() throws Exception {
    PluginConfig existing = new PluginConfig();
    existing.setId(1L);
    existing.setName("Sonar");
    existing.setApiKeyEncrypted("old_enc_key");
    existing.setPluginType(PluginConfig.PluginType.SCANNER);

    ConfigDto dto = new ConfigDto();
    dto.setName("Sonar");
    dto.setApiKey("old_****_key");

    Mockito.when(pluginConfigRepository.findById(1L)).thenReturn(Optional.of(existing));
    Mockito.when(pluginConfigRepository.save(any(PluginConfig.class))).thenReturn(existing);

    mockMvc.perform(put("/api/config/scanners/1")
        .contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(dto)))
        .andExpect(status().isOk());

    // mask 문자열이 있을 경우 encrypt()는 절대로 불리면 안 됨.
    Mockito.verify(encryptionService, Mockito.never()).encrypt(any());
  }
}
