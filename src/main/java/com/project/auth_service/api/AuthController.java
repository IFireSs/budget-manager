package com.project.auth_service.api;

import com.project.auth_service.api.dto.ChangePasswordRequest;
import com.project.auth_service.api.dto.LoginRequest;
import com.project.auth_service.api.dto.RegisterRequest;
import com.project.auth_service.api.dto.SessionResponse;
import com.project.auth_service.api.dto.TokenResponse;
import com.project.auth_service.cookie.SessionIdCookieFactory;
import com.project.auth_service.exceptions.InvalidRefreshTokenException;
import com.project.auth_service.rate_limit.ClientIpResolver;
import com.project.auth_service.service.AuthService;
import com.project.auth_service.cookie.RefreshCookieFactory;
import com.project.auth_service.service.JwtClaims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final RefreshCookieFactory refreshCookieFactory;
    private final SessionIdCookieFactory sessionIdCookieFactory;
    private final ClientIpResolver clientIpResolver;

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> register(@Valid @RequestBody RegisterRequest registerRequest,
                                               HttpServletRequest request,
                                               @RequestHeader(value = "User-Agent", required = false) String userAgent,
                                               @RequestHeader(value = HttpHeaders.ORIGIN, required = false) String origin) {
        AuthService.AuthResult authResult = authService.register(AuthService.RegisterCommand.builder()
                .username(registerRequest.getUsername())
                .email(registerRequest.getEmail())
                .password(registerRequest.getPassword())
                .clientId(registerRequest.getClientId())
                .sessionId(UUID.randomUUID().toString())
                .ip(clientIpResolver.resolve(request))
                .userAgent(userAgent)
                .origin(origin)
                .build());

        return getOkAuthResponseEntity(authResult);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest loginRequest,
                                               HttpServletRequest request,
                                               @RequestHeader(value = "User-Agent", required = false) String userAgent,
                                               @RequestHeader(value = HttpHeaders.ORIGIN, required = false) String origin) {

        AuthService.AuthResult authResult = authService.login(AuthService.LoginCommand.builder()
                .username(loginRequest.getUsername())
                .password(loginRequest.getPassword())
                .clientId(loginRequest.getClientId())
                .sessionId(UUID.randomUUID().toString())
                .ip(clientIpResolver.resolve(request))
                .userAgent(userAgent)
                .origin(origin)
                .build());
        return getOkAuthResponseEntity(authResult);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @CookieValue(name = "refresh_token", required = false) String refreshToken,
            @CookieValue(name = "session_id", required = false) String sessionId,
            HttpServletRequest request,
            @RequestHeader(value = "User-Agent", required = false) String userAgent,
            @RequestHeader(value = HttpHeaders.ORIGIN, required = false) String origin,
            @RequestHeader(value = "X-Refresh-Attempt-Id", required = false) String refreshAttemptId){

        if(refreshToken == null){
            throw new InvalidRefreshTokenException();
        }

        AuthService.AuthResult authResult = authService.refresh(AuthService.RefreshCommand.builder()
                .rawRefreshToken(refreshToken)
                .ip(clientIpResolver.resolve(request))
                .userAgent(userAgent)
                .origin(origin)
                .sessionId(sessionId)
                .refreshAttemptId(refreshAttemptId)
                .build());

        return getOkAuthResponseEntity(authResult);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue(name = "refresh_token", required = false) String refreshToken,
                                       @AuthenticationPrincipal Jwt jwt){
        authService.logout(refreshToken, extractJwtSession(jwt));
        return noContentWithClearedAuthCookies();
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(@AuthenticationPrincipal Jwt jwt){
        UUID userId = JwtClaims.userId(jwt);
        authService.logoutAll(userId);
        return noContentWithClearedAuthCookies();
    }

    @PostMapping("/logout-session/{sessionId}")
    public ResponseEntity<Void> logoutSession(@AuthenticationPrincipal Jwt jwt,
                                              @PathVariable String sessionId){
        UUID userId = JwtClaims.userId(jwt);
        authService.logoutSession(userId, sessionId);
        String currentSessionId = JwtClaims.sessionId(jwt);
        if (!sessionId.equals(currentSessionId)) {
            return ResponseEntity.noContent().build();
        }
        return noContentWithClearedAuthCookies();
    }

    @PostMapping("/password/change")
    public ResponseEntity<Void> changePassword(@AuthenticationPrincipal Jwt jwt,
                                               @Valid @RequestBody ChangePasswordRequest request,
                                               HttpServletRequest servletRequest,
                                               @RequestHeader(value = "User-Agent", required = false) String userAgent) {
        authService.changePassword(AuthService.ChangePasswordCommand.builder()
                .userId(JwtClaims.userId(jwt))
                .currentPassword(request.currentPassword())
                .newPassword(request.newPassword())
                .sessionId(JwtClaims.sessionId(jwt))
                .ip(clientIpResolver.resolve(servletRequest))
                .userAgent(userAgent)
                .build());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/sessions")
    public ResponseEntity<List<SessionResponse>> sessions(@AuthenticationPrincipal Jwt jwt){
        UUID userId = JwtClaims.userId(jwt);
        return ResponseEntity.ok().body(authService.sessions(userId));
    }

    @GetMapping("/csrf")
    public Map<String, String> csrf(CsrfToken token) {
        return Map.of("token", token.getToken());
    }


    private ResponseEntity<TokenResponse> getOkAuthResponseEntity(AuthService.AuthResult authResult) {
        ResponseCookie refreshCookie = refreshCookieFactory.buildRefreshCookie(authResult.rawRefreshToken());
        ResponseCookie sessionIdCookie = sessionIdCookieFactory.buildSessionIdCookie(authResult.sessionId());
        return ResponseEntity.ok()
                .headers(headers -> addAuthCookies(headers, refreshCookie, sessionIdCookie))
                .body(TokenResponse.builder()
                        .accessToken(authResult.accessToken())
                        .build());
    }

    private ResponseEntity<Void> noContentWithClearedAuthCookies() {
        ResponseCookie refreshCookie = refreshCookieFactory.clearRefreshCookie();
        ResponseCookie sessionIdCookie = sessionIdCookieFactory.clearSessionIdCookie();
        return ResponseEntity.noContent()
                .headers(headers -> addAuthCookies(headers, refreshCookie, sessionIdCookie))
                .build();
    }

    private void addAuthCookies(HttpHeaders headers, ResponseCookie refreshCookie, ResponseCookie sessionIdCookie) {
        headers.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());
        headers.add(HttpHeaders.SET_COOKIE, sessionIdCookie.toString());
    }

    private AuthService.JwtSession extractJwtSession(Jwt jwt) {
        if (jwt == null) {
            return null;
        }
        UUID userId = JwtClaims.userId(jwt);
        String sessionId = JwtClaims.sessionId(jwt);
        if (userId == null || sessionId == null || sessionId.isBlank()) {
            return null;
        }
        return new AuthService.JwtSession(userId, sessionId);
    }
}
