package com.innowise.authentication_service;

import com.innowise.authentication_service.dto.AuthRequestDto;
import com.innowise.authentication_service.dto.AuthResponseDto;
import com.innowise.authentication_service.dto.RegisterDto;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final JwtService jwtService;

    @PostMapping("/register") // save user credentials
    public ResponseEntity<Void> register(@RequestBody RegisterDto dto) {
        authService.register(dto);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/login") // create token
    public ResponseEntity<AuthResponseDto> login(@RequestBody AuthRequestDto dto) {
        return ResponseEntity.ok(authService.login(dto));
    }

    @PostMapping("/refresh") // refresh token
    public ResponseEntity<AuthResponseDto> refresh(@RequestParam String refreshToken) {
        return ResponseEntity.ok(authService.refresh(refreshToken));
    }

    @GetMapping("/validate") // validate token
    public ResponseEntity<Boolean> validate(@RequestParam String token) {
        try {
            jwtService.validateTokenAndGetClaims(token);
            return ResponseEntity.ok(true);
        } catch (JwtException e) {
            return ResponseEntity.ok(false);
        }
    }
}