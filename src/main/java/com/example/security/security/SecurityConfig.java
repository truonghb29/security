package com.example.security.security;

import com.example.security.security.JwtFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**", "/swagger-ui/**", "/api-docs/**", "/webjars/**", "/v3/api-docs/**", "/user/all").permitAll()
                        .requestMatchers(HttpMethod.GET, "/todos/**").hasRole("USER") // Thay hasAuthority("SCOPE_todos:read") bằng hasRole("USER")
                        .requestMatchers(HttpMethod.POST, "/todos/**").hasRole("USER") // Thay hasAuthority("SCOPE_todos:write") bằng hasRole("USER")
                        .requestMatchers(HttpMethod.PUT, "/todos/**").hasRole("USER") // Thay hasAuthority("SCOPE_todos:write") bằng hasRole("USER")
                        .requestMatchers(HttpMethod.DELETE, "/todos/**").hasRole("USER") // Thay hasAuthority("SCOPE_todos:write") bằng hasRole("USER")
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
