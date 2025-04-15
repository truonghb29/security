package com.example.security.config;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EnvConfig {
    private static final Dotenv dotenv = Dotenv.configure().load();

    public static String get(String key) {
        return dotenv.get(key);
    }
}
