package com.innowise.authentication_service.service;

import com.innowise.authentication_service.dto.AuthRequest;
import com.innowise.authentication_service.dto.AuthResponse;
import com.innowise.authentication_service.dto.RegisterRequest;
import com.innowise.authentication_service.dto.ValidationResponse;

/**
 * Service interface for handling authentication and user registration.
 */
public interface AuthService {

    /**
     * Registers a new user in the authentication system.
     *
     * @param request the registration request containing login, password, userId, and role.
     * @return AuthResponse containing the generated access and refresh tokens.
     * @throws IllegalArgumentException if a user with the given login already exists.
     */
    AuthResponse register(RegisterRequest request);

    /**
     * Authenticates a user and generates JWT tokens.
     *
     * @param request the authentication request containing login and password.
     * @return AuthResponse containing the generated access and refresh tokens.
     * @throws org.springframework.security.authentication.BadCredentialsException if the login or password is incorrect.
     */
    AuthResponse login(AuthRequest request);

    AuthResponse refresh(String refreshToken);
    ValidationResponse validateToken(String token);
}