package com.project.auth_service.exception_handler;

import com.project.auth_service.cookie.RefreshCookieFactory;
import com.project.auth_service.cookie.SessionIdCookieFactory;
import com.project.auth_service.api.dto.ApiErrorResponse;
import com.project.auth_service.exceptions.AuthClientAlreadyExistsException;
import com.project.auth_service.exceptions.AuthClientNotFoundException;
import com.project.auth_service.exceptions.BadCredentialsException;
import com.project.auth_service.exceptions.BannedUserRefreshException;
import com.project.auth_service.exceptions.EmailAlreadyExistsException;
import com.project.auth_service.exceptions.ExpiredRefreshTokenException;
import com.project.auth_service.exceptions.InvalidAuthClientOriginException;
import com.project.auth_service.exceptions.InvalidRefreshTokenException;
import com.project.auth_service.exceptions.InvalidUserBanException;
import com.project.auth_service.exceptions.InvalidClientException;
import com.project.auth_service.exceptions.InvalidCurrentPasswordException;
import com.project.auth_service.exceptions.OriginNotAllowedException;
import com.project.auth_service.exceptions.PasswordReuseNotAllowedException;
import com.project.auth_service.exceptions.RefreshTokenAlreadyProcessedException;
import com.project.auth_service.exceptions.RefreshTokenReuseDetectedException;
import com.project.auth_service.exceptions.UserNotFoundException;
import com.project.auth_service.exceptions.UserAlreadyBannedException;
import com.project.auth_service.exceptions.UserBanForbiddenException;
import com.project.auth_service.exceptions.UserBannedException;
import com.project.auth_service.exceptions.UsernameAlreadyExistsException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RequiredArgsConstructor
@RestControllerAdvice
public class ExceptionAuthHandler {
    private final RefreshCookieFactory refreshCookieFactory;
    private final SessionIdCookieFactory sessionIdCookieFactory;

    @ExceptionHandler({InvalidRefreshTokenException.class,
            ExpiredRefreshTokenException.class,
            RefreshTokenReuseDetectedException.class})
    public ResponseEntity<ApiErrorResponse> handleRefreshAuth(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.SET_COOKIE, refreshCookieFactory.clearRefreshCookie().toString())
                .header(HttpHeaders.SET_COOKIE, sessionIdCookieFactory.clearSessionIdCookie().toString())
                .body(error(errorCode(ex), ex));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiErrorResponse> handleBadCredentials(BadCredentialsException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error("INVALID_CREDENTIALS", ex));
    }

    @ExceptionHandler(BannedUserRefreshException.class)
    public ResponseEntity<ApiErrorResponse> handleBannedRefresh(BannedUserRefreshException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .header(HttpHeaders.SET_COOKIE, refreshCookieFactory.clearRefreshCookie().toString())
                .header(HttpHeaders.SET_COOKIE, sessionIdCookieFactory.clearSessionIdCookie().toString())
                .body(error("USER_BANNED", ex));
    }

    @ExceptionHandler(UserBannedException.class)
    public ResponseEntity<ApiErrorResponse> handleUserBanned(UserBannedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error("USER_BANNED", ex));
    }

    @ExceptionHandler(InvalidUserBanException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidUserBan(InvalidUserBanException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error("INVALID_USER_BAN", ex));
    }

    @ExceptionHandler(UserBanForbiddenException.class)
    public ResponseEntity<ApiErrorResponse> handleUserBanForbidden(UserBanForbiddenException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error("USER_BAN_FORBIDDEN", ex));
    }

    @ExceptionHandler(InvalidClientException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidClient(InvalidClientException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error("INVALID_CLIENT", ex));
    }

    @ExceptionHandler(InvalidCurrentPasswordException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidCurrentPassword(InvalidCurrentPasswordException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error("INVALID_CURRENT_PASSWORD", ex));
    }

    @ExceptionHandler(PasswordReuseNotAllowedException.class)
    public ResponseEntity<ApiErrorResponse> handlePasswordReuseNotAllowed(PasswordReuseNotAllowedException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error("PASSWORD_REUSE_NOT_ALLOWED", ex));
    }

    @ExceptionHandler(InvalidAuthClientOriginException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidAuthClientOrigin(InvalidAuthClientOriginException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error("INVALID_AUTH_CLIENT_ORIGIN", ex));
    }

    @ExceptionHandler(OriginNotAllowedException.class)
    public ResponseEntity<ApiErrorResponse> handleOriginNotAllowed(OriginNotAllowedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error("ORIGIN_NOT_ALLOWED", ex));
    }

    @ExceptionHandler({
            UsernameAlreadyExistsException.class,
            EmailAlreadyExistsException.class,
            AuthClientAlreadyExistsException.class,
            UserAlreadyBannedException.class
    })
    public ResponseEntity<ApiErrorResponse> handleRegistrationConflict(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(error(errorCode(ex), ex));
    }

    @ExceptionHandler(RefreshTokenAlreadyProcessedException.class)
    public ResponseEntity<ApiErrorResponse> handleRefreshAlreadyProcessed(RefreshTokenAlreadyProcessedException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(error("REFRESH_TOKEN_ALREADY_PROCESSED", ex));
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleUserNotFound(UserNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error("USER_NOT_FOUND", ex));
    }

    @ExceptionHandler(AuthClientNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleAuthClientNotFound(AuthClientNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error("AUTH_CLIENT_NOT_FOUND", ex));
    }

    private ApiErrorResponse error(String code, RuntimeException ex) {
        return new ApiErrorResponse(code, ex.getMessage());
    }

    private String errorCode(RuntimeException ex) {
        return switch (ex) {
            case InvalidRefreshTokenException ignored -> "INVALID_REFRESH_TOKEN";
            case ExpiredRefreshTokenException ignored -> "REFRESH_TOKEN_EXPIRED";
            case RefreshTokenReuseDetectedException ignored -> "REFRESH_TOKEN_REUSE_DETECTED";
            case UsernameAlreadyExistsException ignored -> "USERNAME_ALREADY_TAKEN";
            case EmailAlreadyExistsException ignored -> "EMAIL_ALREADY_REGISTERED";
            case UserNotFoundException ignored -> "USER_NOT_FOUND";
            case AuthClientAlreadyExistsException ignored -> "AUTH_CLIENT_ALREADY_EXISTS";
            case AuthClientNotFoundException ignored -> "AUTH_CLIENT_NOT_FOUND";
            case UserAlreadyBannedException ignored -> "USER_ALREADY_BANNED";
            default -> "AUTH_ERROR";
        };
    }
}
