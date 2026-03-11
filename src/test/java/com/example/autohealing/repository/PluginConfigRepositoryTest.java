package com.example.autohealing.repository;

import com.example.autohealing.entity.PluginConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class PluginConfigRepositoryTest {

  @Autowired
  private PluginConfigRepository pluginConfigRepository;

  @Test
  @DisplayName("활성화된 특정 타입의 플러그인 목록을 조회할 수 있어야 한다")
  void findByPluginTypeAndEnabledTrueTest() {
    // given
    PluginConfig scanner1 = new PluginConfig();
    scanner1.setName("Snyk-Scanner");
    scanner1.setPluginType(PluginConfig.PluginType.SCANNER);
    scanner1.setEnabled(true);
    pluginConfigRepository.save(scanner1);

    PluginConfig scanner2 = new PluginConfig();
    scanner2.setName("Disabled-Scanner");
    scanner2.setPluginType(PluginConfig.PluginType.SCANNER);
    scanner2.setEnabled(false);
    pluginConfigRepository.save(scanner2);

    PluginConfig ai1 = new PluginConfig();
    ai1.setName("Gemini-AI");
    ai1.setPluginType(PluginConfig.PluginType.AI_ENGINE);
    ai1.setEnabled(true);
    pluginConfigRepository.save(ai1);

    // when
    List<PluginConfig> activeScanners = pluginConfigRepository
        .findByPluginTypeAndEnabledTrue(PluginConfig.PluginType.SCANNER);

    // then
    assertThat(activeScanners).hasSize(1);
    assertThat(activeScanners.get(0).getName()).isEqualTo("Snyk-Scanner");
  }
}
