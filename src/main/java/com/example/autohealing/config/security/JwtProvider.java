package com.example.autohealing.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtProvider {

  @Value("${jwt.secret}")
  private String secretKey;

  @Value("${jwt.expiration}")
  private long expirationMillis;

  private SecretKey key;

  @PostConstruct
  protected void init() {
    // Generate a cryptographically strong SecretKey from the properties string
    this.key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
  }

  public String generateToken(String username, String role) {
    Date now = new Date();
    Date validity = new Date(now.getTime() + expirationMillis);

    return Jwts.builder()
        .subject(username)
        .claim("role", role)
        .issuedAt(now)
        .expiration(validity)
        .signWith(key)
        .compact();
  }

  public String getRoleFromToken(String token) {
    Claims claims = Jwts.parser()
        .verifyWith(key)
        .build()
        .parseSignedClaims(token)
        .getPayload();
    return claims.get("role", String.class);
  }

  public boolean validateToken(String token) {
    try {
      Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  public String getUsernameFromToken(String token) {
    Claims claims = Jwts.parser()
        .verifyWith(key)
        .build()
        .parseSignedClaims(token)
        .getPayload();
    return claims.getSubject();
  }
}
