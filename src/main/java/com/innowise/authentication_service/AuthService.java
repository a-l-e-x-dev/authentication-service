package com.innowise.authentication_service;

import com.innowise.authentication_service.dto.AuthRequestDto;
import com.innowise.authentication_service.dto.AuthResponseDto;
import com.innowise.authentication_service.dto.RegisterDto;
import com.innowise.authentication_service.entities.AuthCredential;
import com.innowise.authentication_service.repository.AuthCredentialRepository;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AuthCredentialRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public void register(RegisterDto dto) {
        if (repository.findByLogin(dto.getLogin()).isPresent()) {
            throw new RuntimeException("Login already exists");
        }
        AuthCredential creds = new AuthCredential();
        creds.setLogin(dto.getLogin());
        creds.setPassword(passwordEncoder.encode(dto.getPassword()));
        creds.setUserId(dto.getUserId());
        creds.setRole(dto.getRole().toUpperCase());
        repository.save(creds);
    }

    public AuthResponseDto login(AuthRequestDto dto) {
        AuthCredential user = repository.findByLogin(dto.getLogin())
                .orElseThrow(() -> new BadCredentialsException("Invalid login or password"));

        if (!passwordEncoder.matches(dto.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid login or password");
        }

        return new AuthResponseDto(
                jwtService.generateAccessToken(user),
                jwtService.generateRefreshToken(user)
        );
    }

    public AuthResponseDto refresh(String refreshToken) {
        Claims claims = jwtService.validateTokenAndGetClaims(refreshToken);
        AuthCredential user = repository.findByLogin(claims.getSubject())
                .orElseThrow(() -> new RuntimeException("User not found"));

        return new AuthResponseDto(
                jwtService.generateAccessToken(user),
                jwtService.generateRefreshToken(user)
        );
    }
}