package com.example.security.config;

import com.example.security.entity.Todo;
import com.example.security.entity.User;
import com.example.security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.UUID;

@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // Kiểm tra xem collection users có dữ liệu không
        if (userRepository.count() == 0) {
            logger.info("No users found in database. Initializing data...");

            // Khởi tạo user với danh sách Todo
            User user = new User("user", passwordEncoder.encode("password"), Arrays.asList("USER"));
            Todo userTodo1 = new Todo("Learn Spring Boot");
            userTodo1.setId(UUID.randomUUID().toString());
            Todo userTodo2 = new Todo("Build REST API");
            userTodo2.setId(UUID.randomUUID().toString());
            user.getTodos().add(userTodo1);
            user.getTodos().add(userTodo2);
            userRepository.save(user);

            // Khởi tạo admin với danh sách Todo
            User admin = new User("admin", passwordEncoder.encode("admin"), Arrays.asList("USER", "ADMIN"));
            Todo adminTodo1 = new Todo("Configure Security");
            adminTodo1.setId(UUID.randomUUID().toString());
            admin.getTodos().add(adminTodo1);
            userRepository.save(admin);

            logger.info("Data initialized successfully: {}", userRepository.findAll());
        } else {
            logger.info("Users already exist in database. Skipping initialization...");
        }
    }
}
