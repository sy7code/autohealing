package com.example.autohealing.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class EncryptionServiceTest {

  private EncryptionService encryptionService;

  @BeforeEach
  void setUp() {
    encryptionService = new EncryptionService();
    ReflectionTestUtils.setField(encryptionService, "encryptionKey", "test-key-32bytes-123456789012345");
    encryptionService.init();
  }

  @Test
  @DisplayName("문자열 암호화 및 복호화가 정상적으로 이루어져야 한다")
  void encryptAndDecryptTest() {
    // given
    String originalText = "ghp_secure_github_token_123456";

    // when
    String encrypted = encryptionService.encrypt(originalText);
    String decrypted = encryptionService.decrypt(encrypted);

    // then
    assertThat(encrypted).isNotEqualTo(originalText);
    assertThat(decrypted).isEqualTo(originalText);
  }

  @Test
  @DisplayName("잘못된 암호키나 깨진 데이터의 경우 [DECRYPTION_FAILED]를 반환해야 한다 (v15 격리)")
  void decryptionFailureTest() {
    // given
    String invalidCipherText = "InvalidCipherTextNotBase64";

    // when
    String decrypted = encryptionService.decrypt(invalidCipherText);

    // then
    assertThat(decrypted).isEqualTo("[DECRYPTION_FAILED]");
  }

  @Test
  @DisplayName("민감한 정보를 마스킹해야 한다 (v16 방어)")
  void maskTest() {
    // given
    String token = "sk-1234567890abcdef";

    // when
    String masked = encryptionService.mask(token);

    // then
    assertThat(masked).isEqualTo("sk-1****cdef");
    assertThat(masked).doesNotContain("234567890abc");
  }
}
