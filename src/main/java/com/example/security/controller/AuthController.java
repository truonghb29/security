package com.example.security.controller;

import com.example.security.dto.LoginRequest;
import com.example.security.dto.LoginResponse;
import com.example.security.dto.RefreshTokenRequest;
import com.example.security.entity.RefreshToken;
import com.example.security.entity.User;
import com.example.security.repository.UserRepository;
import com.example.security.security.JwtUtil;
import com.example.security.service.RefreshTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest request) {
        logger.info("Login request received for username: {}", request.getUsername());
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
            logger.info("Authentication successful for username: {}", authentication.getName());
            String accessToken = jwtUtil.generateToken(authentication.getName());
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(authentication.getName());
            return new LoginResponse(accessToken, refreshToken.getToken());
        } catch (Exception e) {
            logger.error("Authentication failed for username: {}. Error: {}", request.getUsername(), e.getMessage());
            throw e;
        }
    }

    @PostMapping("/refresh")
    public LoginResponse refreshToken(@RequestBody RefreshTokenRequest request) {
        RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(request.getRefreshToken());
        String accessToken = jwtUtil.generateToken(refreshToken.getUsername());
        return new LoginResponse(accessToken, refreshToken.getToken());
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody RefreshTokenRequest request) {
        logger.info("Logout request received for refresh token: {}", request.getRefreshToken());
        try {
            refreshTokenService.deleteRefreshToken(request.getRefreshToken());
            logger.info("Logout successful: Refresh token deleted");
            return ResponseEntity.ok("Logout successful");
        } catch (Exception e) {
            logger.error("Logout failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body("Logout failed: " + e.getMessage());
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody LoginRequest request) {
        logger.info("Signup request received for username: {}", request.getUsername());
        try {
            // Kiểm tra username đã tồn tại chưa
            if (userRepository.existsByUsername(request.getUsername())) {
                logger.warn("Username already exists: {}", request.getUsername());
                return ResponseEntity.badRequest().body("Username already exists");
            }

            // Tạo user mới
            User user = new User();
            user.setUsername(request.getUsername());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setRoles(Arrays.asList("USER")); // Mặc định role là USER
            userRepository.save(user);

            logger.info("Signup successful for username: {}", request.getUsername());
            return ResponseEntity.ok("Signup successful");
        } catch (Exception e) {
            logger.error("Signup failed for username: {}. Error: {}", request.getUsername(), e.getMessage());
            return ResponseEntity.badRequest().body("Signup failed: " + e.getMessage());
        }
    }
}
