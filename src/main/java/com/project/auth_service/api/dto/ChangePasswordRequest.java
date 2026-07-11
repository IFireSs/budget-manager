package com.project.auth_service.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
        @NotBlank
        String currentPassword,

        @NotBlank
        @Size(min = 8, max = 72)
        String newPassword
) {
}
