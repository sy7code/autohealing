package com.example.autohealing.controller;

import com.example.autohealing.config.security.JwtProvider;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Auth API", description = "Endpoints for login and obtaining JWT tokens")
public class AuthController {

  private final JwtProvider jwtProvider;

  @Value("${admin.username}")
  private String adminUsername;

  @Value("${admin.password}")
  private String adminPassword;

  public AuthController(JwtProvider jwtProvider) {
    this.jwtProvider = jwtProvider;
  }

  @Operation(summary = "Admin Login", description = "Verifies the admin credentials and returns a JWT token.")
  @PostMapping("/login")
  public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
    if (adminUsername.equals(loginRequest.getUsername()) && adminPassword.equals(loginRequest.getPassword())) {
      String token = jwtProvider.generateToken(adminUsername);
      return ResponseEntity.ok(Map.of("token", token));
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid username or password"));
  }

  @Data
  public static class LoginRequest {
    private String username;
    private String password;
  }
}
