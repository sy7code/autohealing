package com.example.autohealing.repository;

import com.example.autohealing.entity.PluginConfig;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PluginConfigRepository extends JpaRepository<PluginConfig, Long> {
  List<PluginConfig> findByPluginTypeAndEnabledTrue(PluginConfig.PluginType type);

  List<PluginConfig> findByPluginType(PluginConfig.PluginType type);

  Optional<PluginConfig> findByName(String name);
}
