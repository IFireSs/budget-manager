package com.project.auth_service.service;

import com.project.auth_service.config.AppSecurityProperties;
import com.project.auth_service.entity.AuthClient;
import com.project.auth_service.entity.RefreshToken;
import com.project.auth_service.enums.AuditEventType;
import com.project.auth_service.exceptions.RefreshTokenAlreadyProcessedException;
import com.project.auth_service.exceptions.BannedUserRefreshException;
import com.project.auth_service.repository.RefreshTokenRepository;
import com.project.auth_service.service.dto.OffsetBasedPageRequest;
import com.project.auth_service.service.dto.SessionFilter;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.project.auth_service.exceptions.ExpiredRefreshTokenException;
import com.project.auth_service.exceptions.InvalidRefreshTokenException;
import com.project.auth_service.exceptions.RefreshTokenReuseDetectedException;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
    private static final String UNKNOWN_USER_AGENT = "unknown";

    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenCrypto refreshTokenCrypto;
    private final RefreshReplayCrypto refreshReplayCrypto;
    private final boolean revokeDetect;
    private final Duration reuseGrace;
    private final boolean requireSessionId;
    private final boolean bindToUserAgent;
    private final boolean bindToIp;
    private final AuditEventService auditEventService;
    private final AuthClientService authClientService;
    private final UserBanService userBanService;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository
                        ,RefreshTokenCrypto refreshTokenCrypto
                        ,RefreshReplayCrypto refreshReplayCrypto
                        ,AppSecurityProperties securityProperties
                        ,AuditEventService auditEventService
                        ,AuthClientService authClientService
                        ,UserBanService userBanService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.refreshTokenCrypto = refreshTokenCrypto;
        this.refreshReplayCrypto = refreshReplayCrypto;
        this.auditEventService = auditEventService;
        this.authClientService = authClientService;
        this.userBanService = userBanService;
        this.revokeDetect = securityProperties.refresh().revokeDetect();
        this.reuseGrace = securityProperties.refresh().reuseGrace();
        this.requireSessionId = securityProperties.refresh().clientBinding().requireSessionId();
        this.bindToUserAgent = securityProperties.refresh().clientBinding().bindToUserAgent();
        this.bindToIp = securityProperties.refresh().clientBinding().bindToIp();
    }

    public String createSession(UUID userId, String sessionId, String ip, String userAgent, AuthClient client) {
        var rawToken = refreshTokenCrypto.generateRawToken();
        var hash = refreshTokenCrypto.hash(rawToken);
        var now = Instant.now();
        String normalizedUserAgent = normalizeUserAgent(userAgent);

        refreshTokenRepository.save(RefreshToken.builder()
                .userId(userId)
                .tokenHash(hash)
                .expiresAt(now.plus(authClientService.refreshTokenTtl(client)))
                .revoked(false)
                .sessionId(sessionId)
                .clientId(client.getClientId())
                .ip(ip)
                .userAgent(normalizedUserAgent)
                .createdAt(now)
                .lastUsedAt(now)
                .build());

        return rawToken;
    }

    public record RotateResult(String rawRefreshToken, UUID userId, String sessionId, String clientId) {
        @Override
        public String toString() {
            return "RotateResult{" +
                    "rawRefreshToken='" + "***" + '\'' +
                    ", userId=" + userId +
                    ", sessionId='" + sessionId + '\'' +
                    ", clientId='" + clientId + '\'' +
                    '}';
        }
    }

    @Transactional(noRollbackFor = RefreshTokenReuseDetectedException.class)
    public RotateResult rotate(String rawRefreshToken,
                               String ip,
                               String userAgent,
                               String origin,
                               String sessionId,
                               String refreshAttemptId) {

        var oldHash = refreshTokenCrypto.hash(rawRefreshToken);
        var old = refreshTokenRepository.findByTokenHashForUpdate(oldHash).orElseThrow(InvalidRefreshTokenException::new);
        var now = Instant.now();
        if (userBanService.isBanned(old.getUserId())) {
            throw new BannedUserRefreshException();
        }
        AuthClient client = authClientService.resolveActiveClient(old.getClientId());
        authClientService.validateOriginAllowed(client, origin);
        String normalizedAttemptId = normalizeAttemptId(refreshAttemptId);
        String normalizedSessionId = normalizeSessionId(sessionId);
        String normalizedUserAgent = normalizeUserAgent(userAgent);
        if (old.getExpiresAt().isBefore(now)) {
            throw new ExpiredRefreshTokenException();
        }
        if (revokeDetect && old.getCompromisedAt() != null) {
            throw new RefreshTokenReuseDetectedException();
        }
        if (requireSessionId && normalizedSessionId == null) {
            throw new InvalidRefreshTokenException();
        }

        boolean sessionMismatch = normalizedSessionId != null && !normalizedSessionId.equals(old.getSessionId());
        boolean ipMismatch = bindToIp && isValueMismatch(old.getIp(), ip);
        boolean uaMismatch = bindToUserAgent && isValueMismatch(old.getUserAgent(), normalizedUserAgent);

        if (sessionMismatch || ipMismatch || uaMismatch) {
            recordRefreshReuseDetected(old, ip, userAgent, mismatchReason(sessionMismatch, ipMismatch, uaMismatch));
            if (sessionMismatch && ipMismatch && uaMismatch) {
                markCompromisedAndKillAllSessionsOnce(old.getUserId(), now, mismatchReason(sessionMismatch, ipMismatch, uaMismatch));
            } else {
                markCompromisedAndKillSessionOnce(old.getUserId(), old.getSessionId(), now, mismatchReason(sessionMismatch, ipMismatch, uaMismatch));
            }
            throw new RefreshTokenReuseDetectedException();
        }
        if (revokeDetect && old.isRevoked()) {
            if (old.getRevokedAt() != null
                    && old.getReplacedByTokenHash() != null
                    && Duration.between(old.getRevokedAt(), now).compareTo(reuseGrace) <= 0) {
                if (sameAttempt(old, normalizedAttemptId, now)) {
                    old.setLastUsedAt(now);
                    return new RotateResult(
                            refreshReplayCrypto.decrypt(old.getRotationResultTokenCipher()),
                            old.getUserId(),
                            old.getSessionId(),
                            old.getClientId()
                    );
                }
                throw new RefreshTokenAlreadyProcessedException();
            }
            if (old.getRevokedAt() != null
                    && old.getReplacedByTokenHash() != null
                    && old.getRotationResultExpiresAt() != null
                    && old.getRotationResultExpiresAt().isAfter(now)) {
                throw new RefreshTokenAlreadyProcessedException();
            }

            markCompromisedAndKillSessionOnce(old.getUserId(), old.getSessionId(), now, "REUSE_DETECTED");
            recordRefreshReuseDetected(old, ip, userAgent, "REUSE_DETECTED");
            throw new RefreshTokenReuseDetectedException();
        }

        var result = createSession(old.getUserId(), old.getSessionId(), ip, normalizedUserAgent, client);

        var newHash = refreshTokenCrypto.hash(result);

        if(!revokeDetect){
            refreshTokenRepository.deleteById(old.getId());
        }else {
            old.setRevoked(true);
            old.setRevokedAt(now);
            old.setReplacedByTokenHash(newHash);
            old.setLastUsedAt(now);
            old.setRotationAttemptId(normalizedAttemptId);
            old.setRotationResultTokenCipher(normalizedAttemptId == null ? null : refreshReplayCrypto.encrypt(result));
            old.setRotationResultExpiresAt(normalizedAttemptId == null ? null : now.plus(reuseGrace));
        }

        return new RotateResult(result, old.getUserId(), old.getSessionId(), old.getClientId());
    }

    @Transactional
    public void revokeByRawToken(String rawRefreshToken) {
        String hash = refreshTokenCrypto.hash(rawRefreshToken);
        if(!revokeDetect){
            refreshTokenRepository.deleteByTokenHash(hash);
            return;
        }
        Optional<RefreshToken> byTokenHashForUpdate = refreshTokenRepository.findByTokenHashForUpdate(hash);
        if (byTokenHashForUpdate.isPresent()) {
            RefreshToken refreshToken = byTokenHashForUpdate.get();
            if(!refreshToken.isRevoked()) {
                Instant now = Instant.now();
                refreshToken.setRevoked(true);
                refreshToken.setRevokedAt(now);
                refreshToken.setLastUsedAt(now);
            }
        }
    }

    @Transactional
    public void revokeAllByUserId(UUID userId, Instant now) {
        if(!revokeDetect){
            refreshTokenRepository.deleteAllByUserId(userId);
        }else{
            refreshTokenRepository.revokeAllActiveByUserId(userId, now);
        }

    }

    @Transactional
    public void revokeAllByUserIdPreservingState(UUID userId, Instant now) {
        refreshTokenRepository.revokeAllActiveByUserId(userId, now);
    }
    
    public List<RefreshToken> findAllByUserIdAndRevokedFalse(UUID userId) {
        return refreshTokenRepository.findAllByUserIdAndRevokedFalse(userId);
    }

    public List<RefreshToken> findAllByUserId(UUID userId, SessionFilter filter, int limit, int offset) {
        Sort sort = Sort.by("createdAt").descending().and(Sort.by("id").descending());

        return refreshTokenRepository.findAll(
                        sessionSpecification(userId, filter, Instant.now()),
                        OffsetBasedPageRequest.capped(limit, offset, sort)
                )
                .stream()
                .toList();
    }

    @Transactional
    public void revokeAllActiveByUserIdAndSessionId(UUID userId, String sessionId, Instant now) {
        if(!revokeDetect){
            refreshTokenRepository.deleteAllByUserIdAndSessionId(userId, sessionId);
        }else {
            refreshTokenRepository.revokeAllActiveByUserIdAndSessionId(userId, sessionId, now);
        }
    }

    @Transactional
    public int revokeOtherActiveSessionsByUserId(UUID userId, String currentSessionId, Instant now) {
        if (currentSessionId == null || currentSessionId.isBlank()) {
            if (!revokeDetect) {
                return refreshTokenRepository.deleteAllByUserId(userId);
            }
            return refreshTokenRepository.revokeAllActiveByUserId(userId, now);
        }
        if(!revokeDetect){
            return refreshTokenRepository.deleteAllByUserIdExceptSessionId(userId, currentSessionId);
        }
        return refreshTokenRepository.revokeAllActiveByUserIdExceptSessionId(userId, currentSessionId, now);
    }

    private void markCompromisedAndKillSessionOnce(UUID userId, String sessionId, Instant now, String reason) {
        int first = refreshTokenRepository.markSessionCompromisedOnce(userId, sessionId, now, reason);

        if (first > 0) {
            if (revokeDetect) {
                refreshTokenRepository.revokeAllActiveByUserIdAndSessionId(userId, sessionId, now);
            } else {
                refreshTokenRepository.deleteAllByUserIdAndSessionId(userId, sessionId);
            }
        }
    }

    private void markCompromisedAndKillAllSessionsOnce(UUID userId, Instant now, String reason) {
        int first = refreshTokenRepository.markAllSessionsCompromisedOnce(userId, now, reason);

        if (first > 0) {
            if (revokeDetect) {
                refreshTokenRepository.revokeAllActiveByUserId(userId, now);
            } else {
                refreshTokenRepository.deleteAllByUserId(userId);
            }
        }
    }

    private String normalizeAttemptId(String refreshAttemptId) {
        if (refreshAttemptId == null || refreshAttemptId.isBlank()) {
            return null;
        }
        return refreshAttemptId.trim();
    }

    private String normalizeSessionId(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return null;
        }
        return sessionId.trim();
    }

    private String normalizeUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return UNKNOWN_USER_AGENT;
        }
        return userAgent.trim();
    }

    private boolean isValueMismatch(String actual, String candidate) {
        return actual != null && candidate != null && !actual.equals(candidate);
    }

    private String mismatchReason(boolean sessionMismatch, boolean ipMismatch, boolean uaMismatch) {
        StringBuilder reason = new StringBuilder();
        if (sessionMismatch) {
            reason.append("SESSION");
        }
        if (ipMismatch) {
            appendReasonSeparator(reason);
            reason.append("IP");
        }
        if (uaMismatch) {
            appendReasonSeparator(reason);
            reason.append("UA");
        }
        reason.append("_MISMATCH");
        return reason.toString();
    }

    private void appendReasonSeparator(StringBuilder reason) {
        if (!reason.isEmpty()) {
            reason.append('_');
        }
    }

    private void recordRefreshReuseDetected(RefreshToken refreshToken, String ip, String userAgent, String reason) {
        auditEventService.record(AuditEventType.REFRESH_TOKEN_REUSE_DETECTED, AuditEventService.AuditEventCommand.builder()
                .actorUserId(refreshToken.getUserId())
                .targetUserId(refreshToken.getUserId())
                .sessionId(refreshToken.getSessionId())
                .ip(ip)
                .userAgent(userAgent)
                .details(Map.of("reason", reason))
                .build());
    }

    private Specification<RefreshToken> sessionSpecification(UUID userId, SessionFilter filter, Instant now) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();
            predicates.add(criteriaBuilder.equal(root.get("userId"), userId));

            if (filter != null && filter.status() != null) {
                switch (filter.status()) {
                    case ACTIVE -> {
                        predicates.add(criteriaBuilder.isFalse(root.get("revoked")));
                        predicates.add(criteriaBuilder.isNull(root.get("compromisedAt")));
                        predicates.add(criteriaBuilder.greaterThan(root.get("expiresAt"), now));
                    }
                    case REVOKED -> predicates.add(criteriaBuilder.isTrue(root.get("revoked")));
                    case EXPIRED -> predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get("expiresAt"), now));
                    case COMPROMISED -> predicates.add(criteriaBuilder.isNotNull(root.get("compromisedAt")));
                }
            }

            return criteriaBuilder.and(predicates.toArray(Predicate[]::new));
        };
    }

    private boolean sameAttempt(RefreshToken refreshToken, String refreshAttemptId, Instant now) {
        return refreshAttemptId != null
                && refreshAttemptId.equals(refreshToken.getRotationAttemptId())
                && refreshToken.getRotationResultTokenCipher() != null
                && refreshToken.getRotationResultExpiresAt() != null
                && !refreshToken.getRotationResultExpiresAt().isBefore(now);
    }
}
