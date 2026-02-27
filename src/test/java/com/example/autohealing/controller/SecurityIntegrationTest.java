package com.example.autohealing.controller;

import com.example.autohealing.config.security.JwtAuthFilter;
import com.example.autohealing.config.security.JwtProvider;
import com.example.autohealing.config.security.SecurityConfig;
import com.example.autohealing.repository.SecurityLogRepository;
import com.example.autohealing.service.DiscordNotificationService;
import com.example.autohealing.service.GithubService;
import com.example.autohealing.service.JiraService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@org.springframework.test.context.ActiveProfiles("test")
@TestPropertySource(properties = {
    "admin.username=testadmin",
    "admin.password=testpassword123",
    "jwt.secret=ThisIsATestSecretKeyForJwtAuthenticationMockingPurposesOnly",
    "jwt.expiration=3600000"
})
public class SecurityIntegrationTest {

  @Autowired
  private WebApplicationContext context;

  private MockMvc mockMvc;

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(context)
        .apply(springSecurity())
        .build();
  }

  @Autowired
  private JwtProvider jwtProvider;

  @MockitoBean
  private SecurityLogRepository securityLogRepository;

  @MockitoBean
  private GithubService githubService;

  @MockitoBean
  private JiraService jiraService;

  @MockitoBean
  private DiscordNotificationService discordNotificationService;

  @Test
  void testLoginSuccessReturnsToken() throws Exception {
    String loginPayload = "{\"username\": \"testadmin\", \"password\": \"testpassword123\"}";

    mockMvc.perform(post("/api/auth/login")
        .contentType(MediaType.APPLICATION_JSON)
        .content(loginPayload))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.token").exists());
  }

  @Test
  void testLoginFailureReturnsUnauthorized() throws Exception {
    String loginPayload = "{\"username\": \"testadmin\", \"password\": \"wrongpassword\"}";

    mockMvc.perform(post("/api/auth/login")
        .contentType(MediaType.APPLICATION_JSON)
        .content(loginPayload))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error").exists());
  }

  @Test
  void testAccessProtectedEndpointWithoutTokenReturnsForbidden() throws Exception {
    mockMvc.perform(get("/api/dashboard/stats"))
        .andExpect(status().isForbidden());
  }

  @Test
  void testAccessProtectedEndpointWithValidTokenReturnsOk() throws Exception {
    String token = jwtProvider.generateToken("testadmin");

    mockMvc.perform(get("/api/dashboard/stats")
        .header("Authorization", "Bearer " + token))
        .andExpect(status().isOk());
  }

  @Test
  void testSwaggerUiIsAccessibleWithoutToken() throws Exception {
    mockMvc.perform(get("/swagger-ui/index.html"))
        .andExpect(status().isOk());
  }
}
