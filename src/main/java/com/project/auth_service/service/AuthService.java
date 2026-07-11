package com.project.auth_service.service;

import com.project.auth_service.api.dto.SessionResponse;
import com.project.auth_service.entity.AuthClient;
import com.project.auth_service.entity.RefreshToken;
import com.project.auth_service.entity.User;
import com.project.auth_service.enums.AuditEventType;
import com.project.auth_service.exceptions.BadCredentialsException;
import com.project.auth_service.exceptions.InvalidCurrentPasswordException;
import com.project.auth_service.exceptions.PasswordReuseNotAllowedException;
import com.project.auth_service.exceptions.RefreshTokenReuseDetectedException;
import com.project.auth_service.exceptions.UserBannedException;
import com.project.auth_service.service.dto.AuthUser;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final AuthUserService authUserService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final AccessTokenService accessTokenService;
    private final AuditEventService auditEventService;
    private final AuthClientService authClientService;
    private final SessionResponseMapper sessionResponseMapper;
    private final UserBanService userBanService;

    public record AuthResult(String accessToken, String rawRefreshToken, String sessionId) {
        @Override public String toString() {
            return "AuthResult[accessToken=***, rawRefreshToken=***, sessionId=" + sessionId + "]";
        }
    }

    @Builder
    public record RegisterCommand(String username,
                                  String email,
                                  String password,
                                  String clientId,
                                  String sessionId,
                                  String ip,
                                  String userAgent,
                                  String origin) {
    }

    @Builder
    public record LoginCommand(String username,
                               String password,
                               String clientId,
                               String sessionId,
                               String ip,
                               String userAgent,
                               String origin) {
    }

    @Builder
    public record RefreshCommand(String rawRefreshToken,
                                 String ip,
                                 String userAgent,
                                 String origin,
                                 String sessionId,
                                 String refreshAttemptId) {
    }

    @Builder
    public record ChangePasswordCommand(UUID userId,
                                        String currentPassword,
                                        String newPassword,
                                        String sessionId,
                                        String ip,
                                        String userAgent) {
    }

    @Transactional
    public AuthResult register(RegisterCommand command){

        AuthClient client = authClientService.resolveActiveClient(command.clientId());
        authClientService.validateOriginAllowed(client, command.origin());
        String passwordHash = passwordEncoder.encode(command.password());
        AuthUser authUser = authUserService.registerLocalUser(command.username(), command.email(), passwordHash);

        UUID userId = authUser.id();
        String accessToken = accessTokenService.issueAccessToken(userId, authUser.username(), authUser.roles(), command.sessionId(), client);
        String rawRefreshToken = refreshTokenService.createSession(userId, command.sessionId(), command.ip(), command.userAgent(), client);
        auditEventService.record(AuditEventType.USER_REGISTERED, AuditEventService.AuditEventCommand.builder()
                .actorUserId(userId)
                .targetUserId(userId)
                .username(authUser.username())
                .sessionId(command.sessionId())
                .ip(command.ip())
                .userAgent(command.userAgent())
                .details(Map.of("clientId", client.getClientId()))
                .build());
        return new AuthResult(accessToken, rawRefreshToken, command.sessionId());
    }

    @Transactional
    public AuthResult login(LoginCommand command) {

        AuthClient client = authClientService.resolveActiveClient(command.clientId());
        authClientService.validateOriginAllowed(client, command.origin());
        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(command.username(), command.password()));
        }catch (AuthenticationException e){
            auditEventService.recordImmediately(AuditEventType.USER_LOGIN_FAILED, AuditEventService.AuditEventCommand.builder()
                    .username(command.username())
                    .ip(command.ip())
                    .userAgent(command.userAgent())
                    .details(Map.of("reason", "BAD_CREDENTIALS", "clientId", client.getClientId()))
                    .build());
            throw new BadCredentialsException();
        }

        AuthUser authUser = authUserService.findByUsername(command.username()).orElseThrow(BadCredentialsException::new);
        if (userBanService.isBanned(authUser.id())) {
            auditEventService.recordImmediately(AuditEventType.USER_LOGIN_FAILED, AuditEventService.AuditEventCommand.builder()
                    .actorUserId(authUser.id())
                    .targetUserId(authUser.id())
                    .username(authUser.username())
                    .ip(command.ip())
                    .userAgent(command.userAgent())
                    .details(Map.of("reason", "USER_BANNED", "clientId", client.getClientId()))
                    .build());
            throw new UserBannedException();
        }
        UUID userId = authUser.id();
        String accessToken = accessTokenService.issueAccessToken(userId, authUser.username(), authUser.roles(), command.sessionId(), client);
        String rawRefreshToken = refreshTokenService.createSession(userId, command.sessionId(), command.ip(), command.userAgent(), client);
        auditEventService.record(AuditEventType.USER_LOGGED_IN, AuditEventService.AuditEventCommand.builder()
                .actorUserId(userId)
                .targetUserId(userId)
                .username(authUser.username())
                .sessionId(command.sessionId())
                .ip(command.ip())
                .userAgent(command.userAgent())
                .details(Map.of("clientId", client.getClientId()))
                .build());
        return new AuthResult(accessToken, rawRefreshToken, command.sessionId());
    }

    @Transactional(noRollbackFor = RefreshTokenReuseDetectedException.class)
    public AuthResult refresh(RefreshCommand command) {
        RefreshTokenService.RotateResult rotateResult = refreshTokenService.rotate(
                command.rawRefreshToken(),
                command.ip(),
                command.userAgent(),
                command.origin(),
                command.sessionId(),
                command.refreshAttemptId()
        );

        UUID userId = rotateResult.userId();
        AuthClient client = authClientService.resolveActiveClient(rotateResult.clientId());
        AuthUser authUser = authUserService.findById(userId).orElseThrow(BadCredentialsException::new);
        String accessToken = accessTokenService.issueAccessToken(userId, authUser.username(), authUser.roles(), rotateResult.sessionId(), client);
        auditEventService.record(AuditEventType.REFRESH_TOKEN_ROTATED, AuditEventService.AuditEventCommand.builder()
                .actorUserId(userId)
                .targetUserId(userId)
                .username(authUser.username())
                .sessionId(rotateResult.sessionId())
                .ip(command.ip())
                .userAgent(command.userAgent())
                .details(Map.of("clientId", client.getClientId()))
                .build());
        return new AuthResult(accessToken, rotateResult.rawRefreshToken(), rotateResult.sessionId());
    }

    @Transactional
    public void logout(String rawRefreshToken){
        if(rawRefreshToken == null){
            return;
        }
        refreshTokenService.revokeByRawToken(rawRefreshToken);
    }

    @Transactional
    public void logout(String rawRefreshToken, JwtSession jwtSession) {
        if (rawRefreshToken != null) {
            refreshTokenService.revokeByRawToken(rawRefreshToken);
            return;
        }
        if (jwtSession != null) {
            refreshTokenService.revokeAllActiveByUserIdAndSessionId(jwtSession.userId(), jwtSession.sessionId(), Instant.now());
            auditEventService.record(AuditEventType.USER_LOGGED_OUT, AuditEventService.AuditEventCommand.builder()
                    .actorUserId(jwtSession.userId())
                    .targetUserId(jwtSession.userId())
                    .sessionId(jwtSession.sessionId())
                    .build());
        }
    }

    @Transactional
    public void logoutAll(UUID userId){
        refreshTokenService.revokeAllByUserId(userId, Instant.now());
        auditEventService.record(AuditEventType.USER_LOGGED_OUT_ALL, AuditEventService.AuditEventCommand.builder()
                .actorUserId(userId)
                .targetUserId(userId)
                .build());
    }

    @Transactional
    public void logoutSession(UUID userId, String sessionId){
        refreshTokenService.revokeAllActiveByUserIdAndSessionId(userId, sessionId, Instant.now());
        auditEventService.record(AuditEventType.SESSION_REVOKED, AuditEventService.AuditEventCommand.builder()
                .actorUserId(userId)
                .targetUserId(userId)
                .sessionId(sessionId)
                .build());
    }

    @Transactional
    public void changePassword(ChangePasswordCommand command) {
        User user = authUserService.findByIdForUpdate(command.userId());
        if (!passwordEncoder.matches(command.currentPassword(), user.getPasswordHash())) {
            recordPasswordChangeFailed(user, command, "INVALID_CURRENT_PASSWORD");
            throw new InvalidCurrentPasswordException();
        }
        if (passwordEncoder.matches(command.newPassword(), user.getPasswordHash())) {
            recordPasswordChangeFailed(user, command, "PASSWORD_REUSE_NOT_ALLOWED");
            throw new PasswordReuseNotAllowedException();
        }

        user.setPasswordHash(passwordEncoder.encode(command.newPassword()));
        int revokedOtherSessions = refreshTokenService.revokeOtherActiveSessionsByUserId(
                user.getId(),
                command.sessionId(),
                Instant.now()
        );
        auditEventService.record(AuditEventType.PASSWORD_CHANGED, AuditEventService.AuditEventCommand.builder()
                .actorUserId(user.getId())
                .targetUserId(user.getId())
                .username(user.getUsername())
                .sessionId(command.sessionId())
                .ip(command.ip())
                .userAgent(command.userAgent())
                .details(Map.of(
                        "selfService", true,
                        "otherSessionsRevoked", revokedOtherSessions
                ))
                .build());
    }

    private void recordPasswordChangeFailed(User user, ChangePasswordCommand command, String reason) {
        auditEventService.recordImmediately(AuditEventType.PASSWORD_CHANGE_FAILED, AuditEventService.AuditEventCommand.builder()
                .actorUserId(user.getId())
                .targetUserId(user.getId())
                .username(user.getUsername())
                .sessionId(command.sessionId())
                .ip(command.ip())
                .userAgent(command.userAgent())
                .details(Map.of(
                        "selfService", true,
                        "reason", reason
                ))
                .build());
    }

    @Transactional(readOnly = true)
    public List<SessionResponse> sessions(UUID userId){
        List<RefreshToken> allByUserIdAndRevokedFalse = refreshTokenService.findAllByUserIdAndRevokedFalse(userId);
        Instant now = Instant.now();
        return allByUserIdAndRevokedFalse.stream()
                .map(refreshToken -> sessionResponseMapper.toResponse(refreshToken, now))
                .toList();
    }

    public record JwtSession(UUID userId, String sessionId) {
    }
}
