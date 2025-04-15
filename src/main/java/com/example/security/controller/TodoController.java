package com.example.security.controller; // Cập nhật package cho phù hợp

import com.example.security.entity.Todo;
import com.example.security.entity.User;
import com.example.security.repository.UserRepository;
import com.example.security.security.JwtUtil; // Thay JwtTokenProvider bằng JwtUtil
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/todos")
public class TodoController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil; // Thay JwtTokenProvider bằng JwtUtil

    // Get all todos for a user
    @GetMapping
    public ResponseEntity<?> getTodos(@RequestHeader("Authorization") String token) {
        // Xử lý token: Loại bỏ "Bearer " từ header
        String jwt = token.startsWith("Bearer ") ? token.substring(7) : token;
        String username = jwtUtil.getUsername(jwt); // Sử dụng JwtUtil
        Optional<User> userOptional = userRepository.findByUsername(username);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            return ResponseEntity.ok(user.getTodos());
        }
        return ResponseEntity.notFound().build();
    }

    // Add a new todo for a user
    @PostMapping
    public ResponseEntity<?> addTodo(@RequestHeader("Authorization") String token, @RequestBody Todo todo) {
        String jwt = token.startsWith("Bearer ") ? token.substring(7) : token;
        String username = jwtUtil.getUsername(jwt);
        Optional<User> userOptional = userRepository.findByUsername(username);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            todo.setId(java.util.UUID.randomUUID().toString());
            user.getTodos().add(todo);
            userRepository.save(user);
            return ResponseEntity.ok(user.getTodos());
        }
        return ResponseEntity.notFound().build();
    }

    // Edit a todo for a user
    @PutMapping("/{todoId}")
    public ResponseEntity<?> editTodo(@RequestHeader("Authorization") String token, @PathVariable String todoId, @RequestBody Todo updatedTodo) {
        String jwt = token.startsWith("Bearer ") ? token.substring(7) : token;
        String username = jwtUtil.getUsername(jwt);
        Optional<User> userOptional = userRepository.findByUsername(username);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            List<Todo> todos = user.getTodos();
            for (int i = 0; i < todos.size(); i++) {
                if (todos.get(i).getId().equals(todoId)) {
                    todos.set(i, updatedTodo);
                    userRepository.save(user);
                    return ResponseEntity.ok(todos);
                }
            }
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.notFound().build();
    }

    // Delete a todo for a user
    @DeleteMapping("/{todoId}")
    public ResponseEntity<?> deleteTodo(@RequestHeader("Authorization") String token, @PathVariable String todoId) {
        String jwt = token.startsWith("Bearer ") ? token.substring(7) : token;
        String username = jwtUtil.getUsername(jwt);
        Optional<User> userOptional = userRepository.findByUsername(username);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            boolean removed = user.getTodos().removeIf(todo -> todo.getId().equals(todoId));
            if (removed) {
                userRepository.save(user);
                return ResponseEntity.ok(user.getTodos());
            }
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.notFound().build();
    }
}
