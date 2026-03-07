package com.example.autohealing.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
public class EncryptionService {

  private static final Logger log = LoggerFactory.getLogger(EncryptionService.class);
  private static final String ALGORITHM = "AES";

  // V12: AES 키는 정확히 32바이트(256비트)여야 부팅 중 InvalidKeyException이 안 터집니다.
  @Value("${plugin.encryption-key:default-dev-key-1234567890123456}")
  private String encryptionKey;

  private SecretKeySpec secretKeySpec;

  @PostConstruct
  public void init() {
    if (encryptionKey.length() != 16 && encryptionKey.length() != 24 && encryptionKey.length() != 32) {
      log.error("치명적 오류: plugin.encryption-key 길이는 16, 24, 32바이트 중 하나여야 합니다 (현재: {}바이트). v12 감사 결과에 따라 서버 기동을 방단합니다.",
          encryptionKey.length());
      throw new IllegalArgumentException("Invalid AES key length: " + encryptionKey.length());
    }
    byte[] keyBytes = encryptionKey.getBytes(StandardCharsets.UTF_8);
    this.secretKeySpec = new SecretKeySpec(keyBytes, ALGORITHM);
  }

  public String encrypt(String plainText) {
    if (plainText == null || plainText.isBlank())
      return null;
    try {
      Cipher cipher = Cipher.getInstance(ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
      byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(encryptedBytes);
    } catch (Exception e) {
      log.error("암호화 중 오류 발생", e);
      throw new RuntimeException("Encryption failed", e);
    }
  }

  public String decrypt(String cipherText) {
    if (cipherText == null || cipherText.isBlank())
      return null;
    try {
      Cipher cipher = Cipher.getInstance(ALGORITHM);
      cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
      byte[] decodedBytes = Base64.getDecoder().decode(cipherText);
      byte[] decryptedBytes = cipher.doFinal(decodedBytes);
      return new String(decryptedBytes, StandardCharsets.UTF_8);
    } catch (Exception e) {
      // v15 "Last Mile": 암호키 불일치, DB 데이터 손상 시 서버가 죽지 않도록 격리 (묵음 처리)
      log.warn("복호화 실패 - 암호키가 변경되었거나 데이터가 손상되었습니다. 묵음 처리: {}", e.getMessage());
      return "[DECRYPTION_FAILED]";
    }
  }

  public String mask(String plainText) {
    if (plainText == null || plainText.length() < 8)
      return "********";
    return plainText.substring(0, 4) + "****" + plainText.substring(plainText.length() - 4);
  }
}
