package com.innowise.authentication_service.service;

import com.innowise.authentication_service.JwtService;
import com.innowise.authentication_service.dto.AuthRequest;
import com.innowise.authentication_service.dto.AuthResponse;
import com.innowise.authentication_service.dto.RegisterRequest;
import com.innowise.authentication_service.dto.ValidationResponse;
import com.innowise.authentication_service.entities.AuthCredential;
import com.innowise.authentication_service.enums.Role;
import com.innowise.authentication_service.exception.UserAlreadyExistsException;
import com.innowise.authentication_service.repository.AuthCredentialRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthCredentialRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Override
    public AuthResponse register(RegisterRequest request) {
        if (repository.findByLogin(request.getLogin()).isPresent()) {
            throw new UserAlreadyExistsException("User with this login already exists");
        }

        AuthCredential credential = new AuthCredential();
        credential.setLogin(request.getLogin());
        credential.setPassword(passwordEncoder.encode(request.getPassword()));
        credential.setUserId(request.getUserId());

        String role = (request.getRole() != null && !request.getRole().isBlank())
                ? request.getRole().toUpperCase()
                : Role.USER.name();
        credential.setRole(role);

        repository.save(credential);

        return generateAndSaveTokens(credential);
    }

    @Override
    public AuthResponse login(AuthRequest request) {
        AuthCredential credential = repository.findByLogin(request.getLogin())
                .orElseThrow(() -> new BadCredentialsException("Invalid login or password"));

        if (!passwordEncoder.matches(request.getPassword(), credential.getPassword())) {
            throw new BadCredentialsException("Invalid login or password");
        }

        return generateAndSaveTokens(credential);
    }

    @Override
    public AuthResponse refresh(String refreshToken) {
        AuthCredential credential = repository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new BadCredentialsException("Invalid or revoked refresh token"));

        if (!jwtService.isTokenValid(refreshToken)) {
            throw new BadCredentialsException("Refresh token is expired or invalid");
        }

        return generateAndSaveTokens(credential);
    }

    @Override
    public ValidationResponse validateToken(String token) {
        if (!jwtService.isTokenValid(token)) {
            return ValidationResponse.builder()
                    .isValid(false)
                    .build();
        }

        Long userId = jwtService.extractUserId(token);
        String role = jwtService.extractRole(token);

        return ValidationResponse.builder()
                .isValid(true)
                .userId(userId)
                .role(role)
                .build();
    }


    private AuthResponse generateAndSaveTokens(AuthCredential credential) {
        String accessToken = jwtService.generateAccessToken(credential);
        String refreshToken = jwtService.generateRefreshToken(credential);

        credential.setRefreshToken(refreshToken);
        repository.save(credential);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    @Transactional
    public void deleteCredentials(String login) {
        repository.deleteByLogin(login);
    }
}