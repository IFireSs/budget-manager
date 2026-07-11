package com.project.auth_service.exceptions;

public class InvalidCurrentPasswordException extends RuntimeException {
    public InvalidCurrentPasswordException() {
        super("Current password is invalid");
    }
}
