package com.example.security.controller;

import com.example.security.entity.User;
import com.example.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/api/hello")
    public String hello() {
        return "Chào mừng đến với hệ thống bảo mật!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/api/admin")
    public String admin() {
        return "Dành riêng cho ADMIN";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/api/user")
    public String user() {
        return "Dành riêng cho USER";
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated()) {
            String username = authentication.getName();
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Create a response without including password
            Map<String, Object> response = new HashMap<>();
            response.put("id", user.getId());
            response.put("username", user.getUsername());
            response.put("roles", user.getRoles());
            response.put("todos", user.getTodos());

            return ResponseEntity.ok(response);
        }

        return ResponseEntity.badRequest().body("User not authenticated");
    }
}
