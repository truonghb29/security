package com.example.security.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

@Component
@Order(1)
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Logger logger = Logger.getLogger(RateLimitingFilter.class.getName());
    // Separate buckets for different endpoints and user types
    private static final Map<String, Bucket> userBuckets = new ConcurrentHashMap<>();
    private static final Map<String, Bucket> ipBuckets = new ConcurrentHashMap<>();
    private static final int USER_MAX_REQUESTS_PER_MINUTE = 10;
    private static final int IP_MAX_REQUESTS_PER_MINUTE = 5; // Stricter limit for unauthenticated requests

    @Autowired
    private JwtUtil jwtUtil;

    private Bucket createNewUserBucket() {
        Refill refill = Refill.intervally(USER_MAX_REQUESTS_PER_MINUTE, Duration.ofMinutes(1));
        Bandwidth limit = Bandwidth.classic(USER_MAX_REQUESTS_PER_MINUTE, refill);
        return Bucket.builder().addLimit(limit).build();
    }

    private Bucket createNewIpBucket() {
        Refill refill = Refill.intervally(IP_MAX_REQUESTS_PER_MINUTE, Duration.ofMinutes(1));
        Bandwidth limit = Bandwidth.classic(IP_MAX_REQUESTS_PER_MINUTE, refill);
        return Bucket.builder().addLimit(limit).build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        String method = request.getMethod();

        // Check if this is a request we need to rate limit
        boolean isLoginRequest = path.startsWith("/auth/login");
        boolean isTodosGetRequest = path.startsWith("/todos") && HttpMethod.GET.matches(method);

        if (!isLoginRequest && !isTodosGetRequest) {
            // Not a rate-limited endpoint
            filterChain.doFilter(request, response);
            return;
        }

        // First try to get username from JWT token
        String username = getUsernameFromRequest(request);
        String clientIp = getClientIp(request);
        String requestType = isLoginRequest ? "login" : "todos";

        // Decide which rate limiting to apply based on authentication status
        boolean isAuthenticated = username != null;
        String bucketKey;
        Bucket bucket;
        int maxRequestsPerMinute;

        if (isAuthenticated) {
            // For authenticated users, use their username for rate limiting
            bucketKey = username + ":" + requestType;
            bucket = userBuckets.computeIfAbsent(bucketKey, k -> {
                logger.info("Creating new rate limit bucket for user: " + username);
                return createNewUserBucket();
            });
            maxRequestsPerMinute = USER_MAX_REQUESTS_PER_MINUTE;
            logger.info("Rate limiting authenticated user: " + username + " for path: " + path);
        } else {
            // For unauthenticated requests, fall back to IP-based limiting
            bucketKey = clientIp + ":" + requestType;
            bucket = ipBuckets.computeIfAbsent(bucketKey, k -> {
                logger.info("Creating new rate limit bucket for IP: " + clientIp);
                return createNewIpBucket();
            });
            maxRequestsPerMinute = IP_MAX_REQUESTS_PER_MINUTE;
            logger.info("Rate limiting unauthenticated request from IP: " + clientIp + " for path: " + path);
        }

        // Log current status
        long availableTokens = bucket.getAvailableTokens();
        logger.info("Rate limit status for " + (isAuthenticated ? "user: " + username : "IP: " + clientIp) +
                " (available tokens: " + availableTokens + ")");

        // Check if the request can be consumed from the bucket
        if (bucket.tryConsume(1)) {
            // Add headers to show rate limit info
            response.addHeader("X-Rate-Limit-Limit", String.valueOf(maxRequestsPerMinute));
            response.addHeader("X-Rate-Limit-Remaining", String.valueOf(bucket.getAvailableTokens()));

            filterChain.doFilter(request, response);
        } else {
            // Properly format the too many requests error
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.addHeader("X-Rate-Limit-Limit", String.valueOf(maxRequestsPerMinute));
            response.addHeader("X-Rate-Limit-Remaining", "0");
            response.addHeader("X-Rate-Limit-Reset", String.valueOf(System.currentTimeMillis() / 1000 + 60));
            response.getWriter().write(
                    "{\"error\": \"Too many requests\", \"message\": \"You have exceeded the rate limit. Please try again later.\"}");

            logger.warning("Rate limit exceeded for " + (isAuthenticated ? "user: " + username : "IP: " + clientIp) +
                    " for path: " + path);
        }
    }

    /**
     * Extracts the username from JWT token in the request
     */
    private String getUsernameFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            if (jwtUtil.validate(token)) {
                return jwtUtil.getUsername(token);
            }
        }

        // Check if user is already authenticated in security context
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() &&
                !"anonymousUser".equals(authentication.getPrincipal().toString())) {
            return authentication.getName();
        }

        return null; // No authenticated user found
    }

    /**
     * Gets the client IP address from the request, checking common headers used by
     * proxies
     */
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_CLIENT_IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }

        // If it's a comma separated list (X-Forwarded-For can contain multiple IPs),
        // take the first one
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }

        logger.info("Resolved client IP: " + ip);
        return ip;
    }
}
