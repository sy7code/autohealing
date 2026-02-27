package com.example.autohealing.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.config.CorsRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;

/**
 * CORS 설정 - Vercel 프론트엔드에서 API 호출을 허용합니다.
 */
@Configuration
public class CorsConfig implements WebFluxConfigurer {

  @Value("${VERCEL_FRONTEND_URL:http://localhost:3000}")
  private String vercelFrontendUrl;

  @Override
  public void addCorsMappings(CorsRegistry registry) {
    registry.addMapping("/api/**")
        .allowedOrigins(vercelFrontendUrl, "http://localhost:3000")
        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
        .allowedHeaders("*")
        .allowCredentials(true)
        .maxAge(3600);
  }
}
