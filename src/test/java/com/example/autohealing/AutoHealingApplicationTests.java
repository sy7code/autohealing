package com.example.autohealing;

import org.junit.jupiter.api.Test;
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
class AutoHealingApplicationTests {

	@MockitoBean
	private SecurityLogRepository securityLogRepository;

	@Test
	void contextLoads() {
	}

}
