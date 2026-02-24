package com.example.autohealing.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import com.example.autohealing.repository.SecurityLogRepository;

@SpringBootTest(properties = {
    "spring.datasource.url=jdbc:h2:mem:testdb",
    "spring.datasource.driverClassName=org.h2.Driver",
    "spring.datasource.username=sa",
    "spring.datasource.password=",
    "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect"
})
@ActiveProfiles("local")
public class DiscordIntegrationTest {

  @Autowired
  private DiscordNotificationService discordNotificationService;

  @MockitoBean
  private SecurityLogRepository securityLogRepository;

  @Test
  void testDiscordWebhook() {
    discordNotificationService.sendEmbedAlert(
        "Auto-Healing 연동 테스트 \uD83D\uDE80",
        "디스코드 웹훅 알림이 정상적으로 연동되었습니다! (이 메시지는 테스트 발송입니다.)\n" +
            "이제 Snyk 취약점 감지 시, AI의 PR 자동 생성 시, 관리자 승인 완료 시 이곳으로 알림이 전송됩니다.",
        65280 // INFO (Green)
    );

    System.out.println("Discord test notification sent.");
  }
}
