package com.innowise.authentication_service.controller;

import com.innowise.authentication_service.dto.AuthRequest;
import com.innowise.authentication_service.dto.AuthResponse;
import com.innowise.authentication_service.dto.RegisterRequest;
import com.innowise.authentication_service.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST Controller for managing authentication operations.
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Endpoint for user registration.
     *
     * @param request JSON containing user registration details (login, password, userId, role).
     * @return ResponseEntity containing Access and Refresh JWT tokens.
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    /**
     * Endpoint for user authentication (login).
     *
     * @param request JSON containing user credentials (login, password).
     * @return ResponseEntity containing Access and Refresh JWT tokens.
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @GetMapping("/validate")
    public ResponseEntity validateToken(@RequestParam String token) {
        return ResponseEntity.ok(authService.validateToken(token));
    }
}