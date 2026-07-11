package com.project.auth_service.exceptions;

public class PasswordReuseNotAllowedException extends RuntimeException {
    public PasswordReuseNotAllowedException() {
        super("New password must be different from current password");
    }
}
