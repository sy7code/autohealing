package com.example.autohealing;

import com.example.autohealing.entity.PluginConfig;
import com.example.autohealing.repository.PluginConfigRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;

@SpringBootApplication
@Profile("db-check")
public class DbCheckApp {
  public static void main(String[] args) {
    SpringApplication.run(DbCheckApp.class, args);
  }

  @Bean
  public CommandLineRunner checkDb(PluginConfigRepository repository) {
    return args -> {
      System.out.println("--- DB Check Started ---");
      repository.findAll().forEach(config -> {
        System.out
            .println("ID: " + config.getId() + ", Name: " + config.getName() + ", Type: " + config.getPluginType());
      });
      System.out.println("--- DB Check Finished ---");
      System.exit(0);
    };
  }
}
