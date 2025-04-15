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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

@RestController
@RequestMapping("/api/auth")
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

    @PostMapping("/logout")
    public void logout(@RequestBody RefreshTokenRequest request) {
        logger.info("Logout request received for refresh token: {}", request.getRefreshToken());
        RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(request.getRefreshToken());
        refreshTokenService.deleteRefreshToken(String.valueOf(refreshToken));
        logger.info("Logout successful for username: {}", refreshToken.getUsername());
    }

    @PostMapping("/signup")
    public void signup(@RequestBody LoginRequest request) {
        logger.info("Signup request received for username: {}", request.getUsername());
        try {
            // Check if the username already exists
            if (userRepository.existsByUsername(request.getUsername())) {
                throw new RuntimeException("Username already exists");
            }

            // Create and save the new user
            User newUser = new User();
            newUser.setUsername(request.getUsername());
            newUser.setPassword(passwordEncoder.encode(request.getPassword()));
            newUser.setRoles(Arrays.asList("USER"));// Encrypt the password
            userRepository.save(newUser);

            logger.info("Signup successful for username: {}", request.getUsername());
        } catch (Exception e) {
            logger.error("Signup failed for username: {}. Error: {}", request.getUsername(), e.getMessage());
            throw e;
        }
    }

    @PostMapping("/refresh")
    public LoginResponse refreshToken(@RequestBody RefreshTokenRequest request) {
        RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(request.getRefreshToken());
        String accessToken = jwtUtil.generateToken(refreshToken.getUsername());
        return new LoginResponse(accessToken, refreshToken.getToken());
    }
}
