package com.example.security.controller;

import com.example.security.entity.Todo;
import com.example.security.entity.User;
import com.example.security.repository.UserRepository;
import com.example.security.security.JwtUtil;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/todos")
@SecurityRequirement(name = "bearerAuth")
public class TodoController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    // Get all todos for a user
    @GetMapping
    public ResponseEntity<List<Todo>> getTodos(
            @RequestHeader("Authorization") @Parameter(hidden = true) String token) {
        Optional<User> userOptional = getUserFromToken(token);
        return userOptional
                .map(user -> ResponseEntity.ok(user.getTodos()))
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    // Add a new todo for a user
    @PostMapping
    public ResponseEntity<List<Todo>> addTodo(
            @RequestHeader("Authorization") @Parameter(hidden = true) String token,
            @Valid @RequestBody Todo todoRequest) {
        try {
            Optional<User> userOptional = getUserFromToken(token);
            if (userOptional.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            }
            Todo todo = new Todo();
            User user = userOptional.get();
            todo.setId(UUID.randomUUID().toString());
            todo.setTitle(todoRequest.getTitle());
            todo.setCompleted(false);
            user.getTodos().add(todo);
            userRepository.save(user);
            return ResponseEntity.status(HttpStatus.CREATED).body(user.getTodos());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    // Edit a todo for a user
    @PutMapping("/{todoId}")
    public ResponseEntity<List<Todo>> editTodo(
            @RequestHeader("Authorization") @Parameter(hidden = true) String token,
            @PathVariable String todoId,
            @Valid @RequestBody Todo updatedTodo) {
        try {
            Optional<User> userOptional = getUserFromToken(token);
            if (userOptional.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            }

            User user = userOptional.get();
            List<Todo> todos = user.getTodos();
            for (int i = 0; i < todos.size(); i++) {
                if (todoId.equals(todos.get(i).getId())) {
                    updatedTodo.setId(todoId);
                    todos.set(i, updatedTodo);
                    userRepository.save(user);
                    return ResponseEntity.ok(todos);
                }
            }
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    @DeleteMapping("/{todoId}")
    public ResponseEntity<List<Todo>> deleteTodo(
            @RequestHeader("Authorization") @Parameter(hidden = true) String token,
            @PathVariable String todoId) {
        try {
            Optional<User> userOptional = getUserFromToken(token);
            if (userOptional.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            }

            User user = userOptional.get();
            boolean removed = user.getTodos().removeIf(todo -> todoId.equals(todo.getId()));
            if (removed) {
                userRepository.save(user);
                return ResponseEntity.ok(user.getTodos());
            }
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
    }

    // Helper method to get user from JWT token
    private Optional<User> getUserFromToken(String token) {
        String jwt = token.startsWith("Bearer ") ? token.substring(7) : token;
        String username = jwtUtil.getUsername(jwt);
        return userRepository.findByUsername(username);
    }

    // Exception handler for malformed JSON
    @ExceptionHandler({
            HttpMessageNotReadableException.class,
            Exception.class
    })
    public ResponseEntity<String> handleExceptions(Exception ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Error processing request");
    }
}
