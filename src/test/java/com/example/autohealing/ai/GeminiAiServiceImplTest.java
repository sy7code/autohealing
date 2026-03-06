package com.example.autohealing.ai;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;
import org.springframework.core.ParameterizedTypeReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GeminiAiServiceImplTest {

  private RestTemplate restTemplate;
  private GeminiAiServiceImpl geminiAiService;

  @BeforeEach
  void setUp() {
    restTemplate = mock(RestTemplate.class);
    geminiAiService = new GeminiAiServiceImpl(restTemplate, "test-api-key", "gemini-1.5-flash");
  }

  @Test
  void testProviderName() {
    assertEquals("GEMINI", geminiAiService.providerName());
  }

  @Test
  void testFixCodeWithoutApiKeyReturnsMock() {
    GeminiAiServiceImpl noKeyService = new GeminiAiServiceImpl(restTemplate, "", "gemini-1.5-flash");
    AiRemediationResult result = noKeyService.fixCode("System.out.println(password);", "password exposure");

    assertNotNull(result);
    assertTrue(result.getFixedCode().contains("[AUTO-HEALING MOCK]"));
    assertTrue(result.getFixedCode().contains("System.out.println(password);"));
    assertTrue(result.getExplanation().contains("GEMINI_API_KEY가 설정되지 않아"));
  }

  @Test
  void testFixCodeSuccessWithValidJson() {
    String validJsonString = "{\n" +
        "  \"fixedCode\": \"System.out.println(\\\"***\\\");\",\n" +
        "  \"explanation\": \"비밀번호를 마스킹 처리했습니다.\"\n" +
        "}";

    // Mock the API response
    Map<String, Object> mockResponseBody = Map.of(
        "candidates", List.of(
            Map.of("content", Map.of(
                "parts", List.of(
                    Map.of("text", validJsonString))))));
    ResponseEntity<Map<String, Object>> responseEntity = ResponseEntity.ok(mockResponseBody);

    @SuppressWarnings("unchecked")
    ParameterizedTypeReference<Map<String, Object>> typeRef = any(ParameterizedTypeReference.class);

    when(restTemplate.exchange(
        any(String.class),
        eq(HttpMethod.POST),
        any(HttpEntity.class),
        typeRef,
        eq("gemini-1.5-flash"),
        eq("test-api-key"))).thenReturn(responseEntity);

    AiRemediationResult result = geminiAiService.fixCode("System.out.println(password);", "password exposure");

    assertNotNull(result);
    assertEquals("System.out.println(\"***\");", result.getFixedCode());
    assertEquals("비밀번호를 마스킹 처리했습니다.", result.getExplanation());
  }

  @Test
  void testFixCodeFallbackWhenJsonFails() {
    // A response that is NOT a valid JSON object matching the requested schema, but
    // contains a markdown code block.
    String invalidJsonWithMarkdown = "This is my explanation.\n```java\nSystem.out.println(\"fixed\");\n```";

    Map<String, Object> mockResponseBody = Map.of(
        "candidates", List.of(
            Map.of("content", Map.of(
                "parts", List.of(
                    Map.of("text", invalidJsonWithMarkdown))))));
    ResponseEntity<Map<String, Object>> responseEntity = ResponseEntity.ok(mockResponseBody);

    @SuppressWarnings("unchecked")
    ParameterizedTypeReference<Map<String, Object>> typeRef = any(ParameterizedTypeReference.class);

    when(restTemplate.exchange(
        any(String.class),
        eq(HttpMethod.POST),
        any(HttpEntity.class),
        typeRef,
        eq("gemini-1.5-flash"),
        eq("test-api-key"))).thenReturn(responseEntity);

    AiRemediationResult result = geminiAiService.fixCode("System.out.println(password);", "password exposure");

    assertNotNull(result);
    assertEquals("System.out.println(\"fixed\");", result.getFixedCode());
    assertTrue(result.getExplanation().contains("수정 내역을 파싱하는데 실패했습니다."));
  }

  @Test
  void testFixCodeApiFailureReturnsOriginalCode() {
    @SuppressWarnings("unchecked")
    ParameterizedTypeReference<Map<String, Object>> typeRef = any(ParameterizedTypeReference.class);

    when(restTemplate.exchange(
        any(String.class),
        eq(HttpMethod.POST),
        any(HttpEntity.class),
        typeRef,
        any(String.class),
        any(String.class))).thenThrow(new RuntimeException("API Connection Failed"));

    String originalCode = "System.out.println(password);";
    AiRemediationResult result = geminiAiService.fixCode(originalCode, "password exposure");

    assertNotNull(result);
    assertEquals(originalCode, result.getFixedCode());
    assertTrue(result.getExplanation().contains("API 호출 중 오류가 발생했습니다"));
  }
}
