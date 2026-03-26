package com.innowise.authentication_service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class Register {

    @NotBlank(message = "Login cannot be empty")
    private String login;

    @NotBlank(message = "Password cannot be empty")
    private String password;

    @NotNull(message = "User ID cannot be null")
    private Long userId;

    @NotBlank(message = "Role cannot be empty")
    private String role;
}