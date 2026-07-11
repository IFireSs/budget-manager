package com.project.auth_service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.project.auth_service.api.dto.RegisterRequest;
import com.project.auth_service.entity.OutboxEvent;
import com.project.auth_service.entity.RefreshToken;
import com.project.auth_service.entity.UserBan;
import com.project.auth_service.enums.AuditEventType;
import com.project.auth_service.enums.OutboxEventStatus;
import com.project.auth_service.enums.UserBanEndType;
import com.project.auth_service.repository.AuditEventRepository;
import com.project.auth_service.repository.RefreshTokenRepository;
import com.project.auth_service.repository.OutboxEventRepository;
import com.project.auth_service.repository.UserBanRepository;
import com.project.auth_service.config.KafkaEventProperties;
import com.project.auth_service.service.OutboxEventService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
class AuthServiceApplicationTests {
    private static final String USER_AGENT = "JUnit";
    private static final String REFRESH_ATTEMPT_HEADER = "X-Refresh-Attempt-Id";
    private static final String TEST_JWT_KEY_ID = "auth-service-test-key";
    private static final String DEFAULT_CLIENT_ID = "auth-service";
    private static final String DEFAULT_AUDIENCE = "auth-service";
    private static final String AUTH_SERVICE_AUDIENCE = "auth-service";
    private static final String SUPER_ADMIN_USERNAME = "bootstrap_super_admin";
    private static final String SUPER_ADMIN_PASSWORD = "Password123!";
    private static final KeyPair TEST_JWT_KEY_PAIR = generateTestKeyPair();
    private static final String TEST_JWT_PRIVATE_KEY = Base64.getEncoder()
            .encodeToString(TEST_JWT_KEY_PAIR.getPrivate().getEncoded());
    private static final String TEST_JWT_PUBLIC_KEY = Base64.getEncoder()
            .encodeToString(TEST_JWT_KEY_PAIR.getPublic().getEncoded());
    private static final String TEST_REFRESH_REPLAY_SECRET = "test-refresh-replay-secret-0123456789";
    private static final String TEST_SCHEMA = "auth_test_" + UUID.randomUUID().toString().replace("-", "");
    private static final AtomicInteger LOGIN_IP_COUNTER = new AtomicInteger(1);

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16")
            .withDatabaseName("authdb")
            .withUsername("bm")
            .withPassword("bm");

    @DynamicPropertySource
    static void registerSecurityProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("app.security.jwt.private-key", () -> TEST_JWT_PRIVATE_KEY);
        registry.add("app.security.jwt.public-key", () -> TEST_JWT_PUBLIC_KEY);
        registry.add("app.security.jwt.key-id", () -> TEST_JWT_KEY_ID);
        registry.add("app.security.refresh.replay-secret", () -> TEST_REFRESH_REPLAY_SECRET);
        registry.add("app.bootstrap.super-admin.enabled", () -> "true");
        registry.add("app.bootstrap.super-admin.username", () -> SUPER_ADMIN_USERNAME);
        registry.add("app.bootstrap.super-admin.email", () -> "bootstrap-super-admin@example.com");
        registry.add("app.bootstrap.super-admin.password", () -> SUPER_ADMIN_PASSWORD);
        registry.add("app.rate-limit.backend", () -> "in-memory");
        registry.add("app.rate-limit.register.capacity", () -> "100");
        registry.add("app.rate-limit.trusted-proxies[0]", () -> "10.0.0.10");
        registry.add("spring.jpa.properties.hibernate.default_schema", () -> TEST_SCHEMA);
        registry.add("spring.flyway.default-schema", () -> TEST_SCHEMA);
        registry.add("spring.flyway.schemas", () -> TEST_SCHEMA);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private OutboxEventRepository outboxEventRepository;

    @Autowired
    private OutboxEventService outboxEventService;

    @Autowired
    private UserBanRepository userBanRepository;

    @Autowired
    private KafkaEventProperties kafkaEventProperties;

    @Test
    void registerReturnsConflictForDuplicateUser() throws Exception {
        CsrfContext csrf = getCsrfContext();

        String username = "test_" + UUID.randomUUID().toString().replace("-", "");
        String payload = objectMapper.writeValueAsString(new RegisterRequest(
                username,
                "Password123!",
                username + "@example.com",
                null
        ));

        mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("USERNAME_ALREADY_TAKEN"))
                .andExpect(jsonPath("$.message").value("Username is already taken"))
                .andExpect(result -> org.junit.jupiter.api.Assertions.assertTrue(
                        result.getResponse().getHeaders(HttpHeaders.SET_COOKIE).isEmpty()
                ));
    }

    @Test
    void issuedAccessTokenContainsClientClaims() throws Exception {
        CsrfContext csrf = getCsrfContext();
        MvcResult registerResult = registerUser(csrf, "client_claims_" + UUID.randomUUID().toString().replace("-", ""));
        JsonNode payload = readTokenPayload(readAccessToken(registerResult));

        org.junit.jupiter.api.Assertions.assertEquals(DEFAULT_CLIENT_ID, payload.get("client_id").asText());
        assertAudienceContains(payload, AUTH_SERVICE_AUDIENCE, DEFAULT_AUDIENCE);
    }

    @Test
    void loginWithUnknownClientReturnsBadRequest() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String payload = """
                {
                  "username": "nobody",
                  "password": "wrong",
                  "clientId": "unknown-client"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CLIENT"))
                .andExpect(jsonPath("$.message").value("Client application is unknown or disabled"));
    }

    @Test
    void refreshIsIdempotentForSameAttemptIdOnly() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "refresh_" + UUID.randomUUID().toString().replace("-", "");
        String registerPayload = objectMapper.writeValueAsString(new RegisterRequest(
                username,
                "Password123!",
                username + "@example.com",
                null
        ));

        MvcResult registerResult = mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerPayload))
                .andExpect(status().isOk())
                .andReturn();

        Cookie originalRefreshCookie = registerResult.getResponse().getCookie("refresh_token");
        Cookie sessionCookie = registerResult.getResponse().getCookie("session_id");
        String attemptId = UUID.randomUUID().toString();

        MvcResult firstRefresh = mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), originalRefreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .header(REFRESH_ATTEMPT_HEADER, attemptId))
                .andExpect(status().isOk())
                .andReturn();

        Cookie firstReplayCookie = firstRefresh.getResponse().getCookie("refresh_token");
        Cookie refreshedSessionCookie = firstRefresh.getResponse().getCookie("session_id");

        MvcResult replaySameAttempt = mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), originalRefreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .header(REFRESH_ATTEMPT_HEADER, attemptId))
                .andExpect(status().isOk())
                .andReturn();

        Cookie replaySameAttemptCookie = replaySameAttempt.getResponse().getCookie("refresh_token");

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), originalRefreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                .header(REFRESH_ATTEMPT_HEADER, UUID.randomUUID().toString()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("REFRESH_TOKEN_ALREADY_PROCESSED"))
                .andExpect(jsonPath("$.message").value("Refresh token was already processed by another request"));

        org.junit.jupiter.api.Assertions.assertNotNull(firstReplayCookie);
        org.junit.jupiter.api.Assertions.assertNotNull(refreshedSessionCookie);
        org.junit.jupiter.api.Assertions.assertEquals(sessionCookie.getValue(), refreshedSessionCookie.getValue());
        org.junit.jupiter.api.Assertions.assertNotNull(replaySameAttemptCookie);
        org.junit.jupiter.api.Assertions.assertEquals(firstReplayCookie.getValue(), replaySameAttemptCookie.getValue());
    }

    @Test
    @org.springframework.transaction.annotation.Transactional
    void refreshCleanupClearsExpiredReplayPayloadButKeepsRevokedRows() throws Exception {
        CsrfContext csrf = getCsrfContext();
        MvcResult registerResult = registerUser(csrf, "refresh_cleanup_" + UUID.randomUUID().toString().replace("-", ""));
        UUID userId = readUuidClaim(readAccessToken(registerResult), "uid");
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        Instant activeReplayExpiresAt = now.plusSeconds(30);

        RefreshToken expiredReplay = refreshTokenRepository.findAllByUserIdAndRevokedFalse(userId)
                .stream()
                .findFirst()
                .orElseThrow();
        expiredReplay.setRevoked(true);
        expiredReplay.setRevokedAt(now.minusSeconds(10));
        expiredReplay.setReplacedByTokenHash("replacement-" + UUID.randomUUID());
        expiredReplay.setRotationAttemptId("attempt-expired");
        expiredReplay.setRotationResultTokenCipher("cipher-expired");
        expiredReplay.setRotationResultExpiresAt(now.minusMillis(1));
        refreshTokenRepository.saveAndFlush(expiredReplay);

        RefreshToken activeReplay = refreshTokenRepository.saveAndFlush(RefreshToken.builder()
                .userId(userId)
                .tokenHash("active-replay-" + UUID.randomUUID())
                .expiresAt(now.plusSeconds(3600))
                .revoked(true)
                .revokedAt(now.minusSeconds(5))
                .replacedByTokenHash("replacement-" + UUID.randomUUID())
                .sessionId(UUID.randomUUID().toString())
                .clientId(DEFAULT_CLIENT_ID)
                .createdAt(now.minusSeconds(10))
                .lastUsedAt(now.minusSeconds(5))
                .rotationAttemptId("attempt-active")
                .rotationResultTokenCipher("cipher-active")
                .rotationResultExpiresAt(activeReplayExpiresAt)
                .build());

        int cleared = refreshTokenRepository.clearExpiredRotationReplayPayloads(now);

        org.junit.jupiter.api.Assertions.assertEquals(1, cleared);

        RefreshToken clearedToken = refreshTokenRepository.findById(expiredReplay.getId()).orElseThrow();
        org.junit.jupiter.api.Assertions.assertTrue(clearedToken.isRevoked());
        org.junit.jupiter.api.Assertions.assertEquals(expiredReplay.getTokenHash(), clearedToken.getTokenHash());
        org.junit.jupiter.api.Assertions.assertNotNull(clearedToken.getReplacedByTokenHash());
        org.junit.jupiter.api.Assertions.assertNull(clearedToken.getRotationAttemptId());
        org.junit.jupiter.api.Assertions.assertNull(clearedToken.getRotationResultTokenCipher());
        org.junit.jupiter.api.Assertions.assertNull(clearedToken.getRotationResultExpiresAt());

        RefreshToken retainedToken = refreshTokenRepository.findById(activeReplay.getId()).orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals("attempt-active", retainedToken.getRotationAttemptId());
        org.junit.jupiter.api.Assertions.assertEquals("cipher-active", retainedToken.getRotationResultTokenCipher());
        org.junit.jupiter.api.Assertions.assertEquals(activeReplayExpiresAt, retainedToken.getRotationResultExpiresAt());
    }

    @Test
    void logoutAllInvalidatesIssuedAccessTokenInStatefulMode() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "logout_all_" + UUID.randomUUID().toString().replace("-", "");
        String registerPayload = objectMapper.writeValueAsString(new RegisterRequest(
                username,
                "Password123!",
                username + "@example.com",
                null
        ));

        MvcResult registerResult = mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerPayload))
                .andExpect(status().isOk())
                .andReturn();

        String accessToken = readAccessToken(registerResult);

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/auth/logout-all")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshWithoutSessionIdReturnsUnauthorizedButKeepsSessionAlive() throws Exception {
        CsrfContext csrf = getCsrfContext();
        MvcResult registerResult = registerUser(csrf, "missing_sid_" + UUID.randomUUID().toString().replace("-", ""));

        Cookie refreshCookie = registerResult.getResponse().getCookie("refresh_token");
        Cookie sessionCookie = registerResult.getResponse().getCookie("session_id");
        String accessToken = readAccessToken(registerResult);

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), refreshCookie)
                .header("X-XSRF-TOKEN", csrf.token())
                .header(HttpHeaders.USER_AGENT, USER_AGENT))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_REFRESH_TOKEN"))
                .andExpect(jsonPath("$.message").value("Refresh token is invalid or has been revoked"));

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), refreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT))
                .andExpect(status().isOk());
    }

    @Test
    void refreshWithDifferentUserAgentRevokesSession() throws Exception {
        CsrfContext csrf = getCsrfContext();
        MvcResult registerResult = registerUser(csrf, "ua_mismatch_" + UUID.randomUUID().toString().replace("-", ""));

        Cookie refreshCookie = registerResult.getResponse().getCookie("refresh_token");
        Cookie sessionCookie = registerResult.getResponse().getCookie("session_id");
        String accessToken = readAccessToken(registerResult);

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), refreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                .header(HttpHeaders.USER_AGENT, "Other-Agent")
                .with(remoteAddr("10.0.0.5")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REFRESH_TOKEN_REUSE_DETECTED"))
                .andExpect(jsonPath("$.message").value("Refresh token reuse detected. All sessions have been revoked"));

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), refreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logoutWithBearerOnlyRevokesCurrentSession() throws Exception {
        CsrfContext csrf = getCsrfContext();
        MvcResult registerResult = registerUser(csrf, "logout_bearer_" + UUID.randomUUID().toString().replace("-", ""));
        String accessToken = readAccessToken(registerResult);

        mockMvc.perform(post("/api/v1/auth/logout")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void authenticatedUserCanChangePassword() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "change_password_" + UUID.randomUUID().toString().replace("-", "");
        MvcResult registerResult = registerUser(csrf, username);
        String oldSessionAccessToken = readAccessToken(registerResult);
        Cookie oldSessionRefreshCookie = registerResult.getResponse().getCookie("refresh_token");
        Cookie oldSessionIdCookie = registerResult.getResponse().getCookie("session_id");
        MvcResult currentSessionLogin = loginUser(csrf, username, "Password123!");
        String accessToken = readAccessToken(currentSessionLogin);
        UUID userId = readUuidClaim(accessToken, "uid");
        String currentSessionId = readStringClaim(accessToken, "sid");
        String newPassword = "NewPassword123!";

        mockMvc.perform(post("/api/v1/auth/password/change")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "currentPassword": "Password123!",
                                  "newPassword": "%s"
                                }
                                """.formatted(newPassword)))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].sessionId").value(currentSessionId))
                .andExpect(jsonPath("$[1]").doesNotExist());

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + oldSessionAccessToken))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), oldSessionRefreshCookie, oldSessionIdCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "%s",
                                  "password": "Password123!"
                                }
                                """.formatted(username))
                        .with(remoteAddr(nextLoginIp())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));

        mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "%s",
                                  "password": "%s"
                                }
                                """.formatted(username, newPassword))
                        .with(remoteAddr(nextLoginIp())))
                .andExpect(status().isOk());

        var auditEvent = auditEventRepository.findAll().stream()
                .filter(event -> event.getEventType() == AuditEventType.PASSWORD_CHANGED)
                .filter(event -> userId.equals(event.getTargetUserId()))
                .findFirst()
                .orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals(userId, auditEvent.getActorUserId());
        org.junit.jupiter.api.Assertions.assertEquals(username, auditEvent.getUsername());
        org.junit.jupiter.api.Assertions.assertTrue(objectMapper.readTree(auditEvent.getDetailsJson()).get("selfService").asBoolean());
        org.junit.jupiter.api.Assertions.assertEquals(1, objectMapper.readTree(auditEvent.getDetailsJson()).get("otherSessionsRevoked").asInt());
    }

    @Test
    void changePasswordRejectsInvalidCurrentPassword() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "change_password_invalid_" + UUID.randomUUID().toString().replace("-", "");
        MvcResult registerResult = registerUser(csrf, username);
        String accessToken = readAccessToken(registerResult);
        UUID userId = readUuidClaim(accessToken, "uid");

        mockMvc.perform(post("/api/v1/auth/password/change")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "currentPassword": "WrongPassword123!",
                                  "newPassword": "NewPassword123!"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CURRENT_PASSWORD"))
                .andExpect(jsonPath("$.message").value("Current password is invalid"));

        mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "%s",
                                  "password": "Password123!"
                                }
                                """.formatted(username))
                        .with(remoteAddr(nextLoginIp())))
                .andExpect(status().isOk());

        var auditEvent = auditEventRepository.findAll().stream()
                .filter(event -> event.getEventType() == AuditEventType.PASSWORD_CHANGE_FAILED)
                .filter(event -> userId.equals(event.getTargetUserId()))
                .findFirst()
                .orElseThrow();
        JsonNode details = objectMapper.readTree(auditEvent.getDetailsJson());
        org.junit.jupiter.api.Assertions.assertEquals(userId, auditEvent.getActorUserId());
        org.junit.jupiter.api.Assertions.assertEquals(username, auditEvent.getUsername());
        org.junit.jupiter.api.Assertions.assertEquals("INVALID_CURRENT_PASSWORD", details.get("reason").asText());
        org.junit.jupiter.api.Assertions.assertTrue(details.get("selfService").asBoolean());
    }

    @Test
    void changePasswordRejectsSamePassword() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "change_password_same_" + UUID.randomUUID().toString().replace("-", "");
        MvcResult registerResult = registerUser(csrf, username);
        String accessToken = readAccessToken(registerResult);
        UUID userId = readUuidClaim(accessToken, "uid");

        mockMvc.perform(post("/api/v1/auth/password/change")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "currentPassword": "Password123!",
                                  "newPassword": "Password123!"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("PASSWORD_REUSE_NOT_ALLOWED"))
                .andExpect(jsonPath("$.message").value("New password must be different from current password"));

        var auditEvent = auditEventRepository.findAll().stream()
                .filter(event -> event.getEventType() == AuditEventType.PASSWORD_CHANGE_FAILED)
                .filter(event -> userId.equals(event.getTargetUserId()))
                .findFirst()
                .orElseThrow();
        JsonNode details = objectMapper.readTree(auditEvent.getDetailsJson());
        org.junit.jupiter.api.Assertions.assertEquals(userId, auditEvent.getActorUserId());
        org.junit.jupiter.api.Assertions.assertEquals(username, auditEvent.getUsername());
        org.junit.jupiter.api.Assertions.assertEquals("PASSWORD_REUSE_NOT_ALLOWED", details.get("reason").asText());
        org.junit.jupiter.api.Assertions.assertTrue(details.get("selfService").asBoolean());
    }

    @Test
    void accessTokenWithWrongIssuerIsRejected() throws Exception {
        CsrfContext csrf = getCsrfContext();
        MvcResult registerResult = registerUser(csrf, "wrong_issuer_" + UUID.randomUUID().toString().replace("-", ""));
        JsonNode validBody = objectMapper.readTree(registerResult.getResponse().getContentAsString());
        String validAccessToken = validBody.get("accessToken").asText();
        String wrongIssuerToken = issueAccessTokenWithWrongIssuer(validAccessToken, "other-issuer");

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + wrongIssuerToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void accessTokenWithoutAuthServiceAudienceIsRejected() throws Exception {
        CsrfContext csrf = getCsrfContext();
        MvcResult registerResult = registerUser(csrf, "wrong_audience_" + UUID.randomUUID().toString().replace("-", ""));
        String validAccessToken = readAccessToken(registerResult);
        String wrongAudienceToken = issueAccessToken(validAccessToken, "auth-service", List.of("other-service"));

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + wrongAudienceToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void jwksEndpointIsPublicAndContainsPublicKeyOnly() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").value(TEST_JWT_KEY_ID))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].d").doesNotExist());
    }

    @Test
    void actuatorReadinessEndpointIsPublic() throws Exception {
        mockMvc.perform(get("/actuator/health/readiness"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void superAdminCanGrantAndRevokeAdminRole() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "admin_candidate_" + UUID.randomUUID().toString().replace("-", "");
        MvcResult registerResult = registerUser(csrf, username);
        String userAccessToken = readAccessToken(registerResult);
        UUID userId = readUuidClaim(userAccessToken, "uid");

        mockMvc.perform(get("/api/v1/admin/users")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + userAccessToken))
                .andExpect(status().isForbidden());

        String superAdminAccessToken = readAccessToken(loginUser(csrf, SUPER_ADMIN_USERNAME, SUPER_ADMIN_PASSWORD));
        UUID superAdminUserId = readUuidClaim(superAdminAccessToken, "uid");

        mockMvc.perform(get("/api/v1/admin/users")
                        .param("query", SUPER_ADMIN_USERNAME)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].roles[?(@ == 'SUPER_ADMIN')]").exists())
                .andExpect(jsonPath("$[0].roles[?(@ == 'USER')]").doesNotExist());

        mockMvc.perform(put("/api/v1/admin/users/{userId}/roles/admin", userId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/admin/users")
                        .param("query", username)
                        .param("role", "ADMIN")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(userId.toString()))
                .andExpect(jsonPath("$[0].roles[?(@ == 'ADMIN')]").exists());

        mockMvc.perform(get("/api/v1/admin/users/{userId}/sessions", userId)
                        .param("status", "ACTIVE")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].sessionId").exists())
                .andExpect(jsonPath("$[0].clientId").value(DEFAULT_CLIENT_ID))
                .andExpect(jsonPath("$[0].status").value("ACTIVE"))
                .andExpect(jsonPath("$[0].revoked").value(false));

        mockMvc.perform(get("/api/v1/admin/audit-events")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].eventType").value("ADMIN_ROLE_GRANTED"))
                .andExpect(jsonPath("$[0].actorUserId").exists())
                .andExpect(jsonPath("$[0].targetUserId").value(userId.toString()));

        mockMvc.perform(get("/api/v1/admin/audit-events")
                        .param("eventType", "ADMIN_ROLE_GRANTED")
                        .param("actorUserId", String.valueOf(superAdminUserId))
                        .param("targetUserId", String.valueOf(userId))
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].eventType").value("ADMIN_ROLE_GRANTED"))
                .andExpect(jsonPath("$[0].actorUserId").value(superAdminUserId.toString()))
                .andExpect(jsonPath("$[0].targetUserId").value(userId.toString()));

        mockMvc.perform(get("/api/v1/admin/audit-events")
                        .param("eventType", "SUPER_ADMIN_BOOTSTRAPPED")
                        .param("targetUserId", String.valueOf(superAdminUserId))
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].eventType").value("SUPER_ADMIN_BOOTSTRAPPED"))
                .andExpect(jsonPath("$[0].targetUserId").value(superAdminUserId.toString()))
                .andExpect(jsonPath("$[0].username").value(SUPER_ADMIN_USERNAME));

        String adminAccessToken = readAccessToken(loginUser(csrf, readStringClaim(userAccessToken, "sub"), "Password123!"));

        mockMvc.perform(get("/api/v1/admin/users")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminAccessToken))
                .andExpect(status().isOk());

        mockMvc.perform(delete("/api/v1/admin/users/{userId}/roles/admin", userId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminAccessToken))
                .andExpect(status().isForbidden());

        mockMvc.perform(delete("/api/v1/admin/users/{userId}/roles/admin", userId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/admin/users")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminAccessToken))
                .andExpect(status().isUnauthorized());

        String userAccessTokenAfterRevoke = readAccessToken(loginUser(csrf, readStringClaim(userAccessToken, "sub"), "Password123!"));

        mockMvc.perform(get("/api/v1/admin/users")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + userAccessTokenAfterRevoke))
                .andExpect(status().isForbidden());
    }

    @Test
    void superAdminCanBanAndUnbanUser() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "banned_user_" + UUID.randomUUID().toString().replace("-", "");
        MvcResult registerResult = registerUser(csrf, username);
        String userAccessToken = readAccessToken(registerResult);
        UUID userId = readUuidClaim(userAccessToken, "uid");
        Cookie refreshCookie = registerResult.getResponse().getCookie("refresh_token");
        Cookie sessionCookie = registerResult.getResponse().getCookie("session_id");
        String superAdminAccessToken = readAccessToken(loginUser(csrf, SUPER_ADMIN_USERNAME, SUPER_ADMIN_PASSWORD));

        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", userId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "reason": "Repeated abuse"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(userId.toString()))
                .andExpect(jsonPath("$.banProtected").value(false))
                .andExpect(jsonPath("$.activeBan.reason").value("Repeated abuse"))
                .andExpect(jsonPath("$.activeBan.expiresAt").doesNotExist());

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + userAccessToken))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .cookie(csrf.cookie(), refreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("USER_BANNED"))
                .andExpect(jsonPath("$.message").value("User is banned"));

        String loginPayload = """
                {
                  "username": "%s",
                  "password": "Password123!"
                }
                """.formatted(username);

        mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginPayload)
                        .with(remoteAddr(nextLoginIp())))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("USER_BANNED"))
                .andExpect(jsonPath("$.message").value("User is banned"));

        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", userId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "reason": "Duplicate ban"
                                }
                                """))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("USER_ALREADY_BANNED"));

        mockMvc.perform(delete("/api/v1/admin/users/{userId}/ban", userId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeBan").doesNotExist());

        mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginPayload)
                        .with(remoteAddr(nextLoginIp())))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/admin/audit-events")
                        .param("eventType", "USER_BANNED")
                        .param("targetUserId", userId.toString())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].details.reason").value("Repeated abuse"))
                .andExpect(jsonPath("$[0].details.permanent").value(true))
                .andExpect(jsonPath("$[0].details.sessionsRevoked").value(true));
    }

    @Test
    void expiredBanIsEndedBeforeCreatingReplacement() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "reban_user_" + UUID.randomUUID().toString().replace("-", "");
        MvcResult registerResult = registerUser(csrf, username);
        UUID userId = readUuidClaim(readAccessToken(registerResult), "uid");
        String superAdminAccessToken = readAccessToken(loginUser(csrf, SUPER_ADMIN_USERNAME, SUPER_ADMIN_PASSWORD));
        UUID superAdminId = readUuidClaim(superAdminAccessToken, "uid");
        Instant now = Instant.now();

        UserBan expiredBan = userBanRepository.saveAndFlush(UserBan.builder()
                .userId(userId)
                .createdAt(now.minusSeconds(7200))
                .expiresAt(now.minusSeconds(3600))
                .reason("Expired temporary ban")
                .createdBy(superAdminId)
                .build());

        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", userId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "reason": "Replacement ban"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeBan.reason").value("Replacement ban"));

        List<UserBan> userBans = userBanRepository.findAll().stream()
                .filter(ban -> ban.getUserId().equals(userId))
                .toList();
        org.junit.jupiter.api.Assertions.assertEquals(2, userBans.size());

        UserBan endedBan = userBans.stream()
                .filter(ban -> ban.getId().equals(expiredBan.getId()))
                .findFirst()
                .orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals(endedBan.getExpiresAt(), endedBan.getEndedAt());
        org.junit.jupiter.api.Assertions.assertEquals(UserBanEndType.EXPIRED, endedBan.getEndType());
        org.junit.jupiter.api.Assertions.assertNull(endedBan.getEndedBy());

        UserBan replacementBan = userBans.stream()
                .filter(ban -> ban.getEndedAt() == null)
                .findFirst()
                .orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals("Replacement ban", replacementBan.getReason());
        org.junit.jupiter.api.Assertions.assertEquals(1,
                userBans.stream().filter(ban -> ban.getEndedAt() == null).count());
    }

    @Test
    void banPermissionsProtectPrivilegedAndBootstrapUsers() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String superAdminAccessToken = readAccessToken(loginUser(csrf, SUPER_ADMIN_USERNAME, SUPER_ADMIN_PASSWORD));
        UUID superAdminUserId = readUuidClaim(superAdminAccessToken, "uid");

        String adminUsername = "ban_admin_" + UUID.randomUUID().toString().replace("-", "");
        UUID adminUserId = readUuidClaim(readAccessToken(registerUser(csrf, adminUsername)), "uid");
        mockMvc.perform(put("/api/v1/admin/users/{userId}/roles/admin", adminUserId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isNoContent());
        String adminAccessToken = readAccessToken(loginUser(csrf, adminUsername, "Password123!"));

        String regularUsername = "ban_target_" + UUID.randomUUID().toString().replace("-", "");
        UUID regularUserId = readUuidClaim(readAccessToken(registerUser(csrf, regularUsername)), "uid");
        String expiresAt = Instant.now().plusSeconds(3600).toString();

        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", regularUserId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "expiresAt": "%s",
                                  "reason": "Temporary moderation action"
                                }
                """.formatted(expiresAt)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeBan.expiresAt").exists());

        mockMvc.perform(delete("/api/v1/admin/users/{userId}/ban", regularUserId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminAccessToken))
                .andExpect(status().isOk());

        String secondAdminUsername = "ban_admin_target_" + UUID.randomUUID().toString().replace("-", "");
        UUID secondAdminUserId = readUuidClaim(readAccessToken(registerUser(csrf, secondAdminUsername)), "uid");
        mockMvc.perform(put("/api/v1/admin/users/{userId}/roles/admin", secondAdminUserId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isNoContent());

        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", secondAdminUserId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "reason": "Not allowed"
                                }
                                """))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("USER_BAN_FORBIDDEN"));

        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", secondAdminUserId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "reason": "Super admin moderation"
                                }
                                """))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/admin/users/{userId}", superAdminUserId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.banProtected").value(true));

        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", superAdminUserId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "reason": "Self ban"
                                }
                                """))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("USER_BAN_FORBIDDEN"));

        mockMvc.perform(put("/api/v1/admin/users/{userId}/ban", superAdminUserId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "reason": "Bootstrap ban"
                                }
                                """))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("USER_BAN_FORBIDDEN"))
                .andExpect(jsonPath("$.message").value("User is protected from bans"));
    }

    @Test
    void superAdminCanManageAuthClients() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String superAdminAccessToken = readAccessToken(loginUser(csrf, SUPER_ADMIN_USERNAME, SUPER_ADMIN_PASSWORD));
        String clientId = "test-client-" + UUID.randomUUID().toString().replace("-", "");
        String audience = "test-audience-" + UUID.randomUUID().toString().replace("-", "");
        String createPayload = """
                {
                  "clientId": "%s",
                  "name": "Test Client",
                  "enabled": true,
                  "accessTokenTtlSeconds": 300,
                  "refreshTokenTtlSeconds": 86400,
                  "tokenAudience": "%s",
                  "allowedOrigins": ["http://localhost:5173"]
                }
                """.formatted(clientId, audience);

        mockMvc.perform(post("/api/v1/admin/auth-clients")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientId").value(clientId))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.tokenAudience").value(audience))
                .andExpect(jsonPath("$.allowedOrigins[0]").value("http://localhost:5173"));

        mockMvc.perform(get("/api/v1/admin/auth-clients/{clientId}", clientId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientId").value(clientId));

        String username = "client_user_" + UUID.randomUUID().toString().replace("-", "");
        String registerPayload = objectMapper.writeValueAsString(new RegisterRequest(
                username,
                "Password123!",
                username + "@example.com",
                clientId
        ));

        MvcResult registerResult = mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerPayload))
                .andExpect(status().isOk())
                .andReturn();

        String clientAccessToken = readAccessToken(registerResult);
        JsonNode clientTokenPayload = readTokenPayload(clientAccessToken);
        org.junit.jupiter.api.Assertions.assertEquals(clientId, clientTokenPayload.get("client_id").asText());
        assertAudienceContains(clientTokenPayload, AUTH_SERVICE_AUDIENCE, audience);

        String adminUsername = "client_admin_" + UUID.randomUUID().toString().replace("-", "");
        MvcResult adminRegisterResult = registerUser(csrf, adminUsername);
        UUID adminUserId = readUuidClaim(readAccessToken(adminRegisterResult), "uid");

        mockMvc.perform(put("/api/v1/admin/users/{userId}/roles/admin", adminUserId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isNoContent());

        String adminAccessToken = readAccessToken(loginUser(csrf, adminUsername, "Password123!"));
        mockMvc.perform(post("/api/v1/admin/auth-clients/{clientId}/disable", clientId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminAccessToken))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/v1/admin/auth-clients/{clientId}/disable", clientId)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false));

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + clientAccessToken))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "%s",
                                  "password": "Password123!",
                                  "clientId": "%s"
                                }
                                """.formatted(username, clientId)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_CLIENT"));

        mockMvc.perform(get("/api/v1/admin/audit-events")
                        .param("eventType", "AUTH_CLIENT_DISABLED")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].eventType").value("AUTH_CLIENT_DISABLED"));
    }

    @Test
    void accessTokenTtlIsCappedByGlobalSetting() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String superAdminAccessToken = readAccessToken(loginUser(csrf, SUPER_ADMIN_USERNAME, SUPER_ADMIN_PASSWORD));
        String clientId = "ttl-client-" + UUID.randomUUID().toString().replace("-", "");
        String audience = "ttl-audience-" + UUID.randomUUID().toString().replace("-", "");

        mockMvc.perform(post("/api/v1/admin/auth-clients")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "clientId": "%s",
                                  "name": "TTL Test Client",
                                  "enabled": true,
                                  "accessTokenTtlSeconds": 86400,
                                  "refreshTokenTtlSeconds": 86400,
                                  "tokenAudience": "%s",
                                  "allowedOrigins": ["http://localhost:5173"]
                                }
                                """.formatted(clientId, audience)))
                .andExpect(status().isOk());

        String username = "ttl_user_" + UUID.randomUUID().toString().replace("-", "");
        String registerPayload = objectMapper.writeValueAsString(new RegisterRequest(
                username,
                "Password123!",
                username + "@example.com",
                clientId
        ));

        MvcResult registerResult = mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerPayload))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode tokenPayload = readTokenPayload(readAccessToken(registerResult));
        long ttlSeconds = tokenPayload.get("exp").asLong() - tokenPayload.get("iat").asLong();
        org.junit.jupiter.api.Assertions.assertEquals(600, ttlSeconds);
    }

    @Test
    void authClientOriginValidationRejectsPaths() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String superAdminAccessToken = readAccessToken(loginUser(csrf, SUPER_ADMIN_USERNAME, SUPER_ADMIN_PASSWORD));
        String clientId = "invalid-origin-client-" + UUID.randomUUID().toString().replace("-", "");

        mockMvc.perform(post("/api/v1/admin/auth-clients")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "clientId": "%s",
                                  "name": "Invalid Origin Client",
                                  "enabled": true,
                                  "accessTokenTtlSeconds": 300,
                                  "refreshTokenTtlSeconds": 86400,
                                  "tokenAudience": "invalid-origin-audience",
                                  "allowedOrigins": ["https://app.example.test/login"]
                                }
                                """.formatted(clientId)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_AUTH_CLIENT_ORIGIN"));
    }

    @Test
    void corsAllowsOriginsAddedBySuperAdmin() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String superAdminAccessToken = readAccessToken(loginUser(csrf, SUPER_ADMIN_USERNAME, SUPER_ADMIN_PASSWORD));
        String clientId = "cors-client-" + UUID.randomUUID().toString().replace("-", "");
        String origin = "https://cors-%s.example.test".formatted(UUID.randomUUID().toString().replace("-", ""));

        createAuthClient(superAdminAccessToken, clientId, origin);

        mockMvc.perform(options("/api/v1/auth/login")
                        .header(HttpHeaders.ORIGIN, origin)
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "content-type,x-xsrf-token"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
    }

    @Test
    void corsRejectsUnknownOrigin() throws Exception {
        String origin = "https://unknown-%s.example.test".formatted(UUID.randomUUID().toString().replace("-", ""));

        mockMvc.perform(options("/api/v1/auth/login")
                        .header(HttpHeaders.ORIGIN, origin)
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "content-type,x-xsrf-token"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    void authRequestOriginMustMatchResolvedClient() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String superAdminAccessToken = readAccessToken(loginUser(csrf, SUPER_ADMIN_USERNAME, SUPER_ADMIN_PASSWORD));
        String clientId = "origin-client-" + UUID.randomUUID().toString().replace("-", "");
        String origin = "https://origin-%s.example.test".formatted(UUID.randomUUID().toString().replace("-", ""));

        createAuthClient(superAdminAccessToken, clientId, origin);

        String allowedUsername = "origin_allowed_" + UUID.randomUUID().toString().replace("-", "");
        String allowedPayload = objectMapper.writeValueAsString(new RegisterRequest(
                allowedUsername,
                "Password123!",
                allowedUsername + "@example.com",
                clientId
        ));

        MvcResult allowedRegisterResult = mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .header(HttpHeaders.ORIGIN, origin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(allowedPayload))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin))
                .andReturn();

        String clientAccessToken = readAccessToken(allowedRegisterResult);
        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + clientAccessToken)
                        .header(HttpHeaders.ORIGIN, origin))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin));

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + clientAccessToken)
                        .header(HttpHeaders.ORIGIN, "http://localhost:5173"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ORIGIN_NOT_ALLOWED"));

        String blockedUsername = "origin_blocked_" + UUID.randomUUID().toString().replace("-", "");
        String blockedPayload = objectMapper.writeValueAsString(new RegisterRequest(
                blockedUsername,
                "Password123!",
                blockedUsername + "@example.com",
                DEFAULT_CLIENT_ID
        ));

        mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .header(HttpHeaders.ORIGIN, origin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(blockedPayload))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("ORIGIN_NOT_ALLOWED"))
                .andExpect(jsonPath("$.message").value("Origin is not allowed for this client application"));
    }

    @Test
    void badLoginDoesNotClearExistingCookies() throws Exception {
        CsrfContext csrf = getCsrfContext();
        MvcResult registerResult = registerUser(csrf, "bad_login_" + UUID.randomUUID().toString().replace("-", ""));
        Cookie refreshCookie = registerResult.getResponse().getCookie("refresh_token");
        Cookie sessionCookie = registerResult.getResponse().getCookie("session_id");

        String payload = """
                {
                  "username": "nobody",
                  "password": "wrong"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie(), refreshCookie, sessionCookie)
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message").value("Invalid username or password"))
                .andExpect(result -> org.junit.jupiter.api.Assertions.assertTrue(
                        result.getResponse().getHeaders(HttpHeaders.SET_COOKIE).isEmpty()
                ));
    }

    @Test
    void failedLoginAuditEventIsPersisted() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "failed_audit_" + UUID.randomUUID().toString().replace("-", "");

        mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "%s",
                                  "password": "wrong"
                                }
                                """.formatted(username)))
                .andExpect(status().isUnauthorized());

        String superAdminAccessToken = readAccessToken(loginUser(csrf, SUPER_ADMIN_USERNAME, SUPER_ADMIN_PASSWORD));

        mockMvc.perform(get("/api/v1/admin/audit-events")
                        .param("eventType", "USER_LOGIN_FAILED")
                        .param("username", username)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].eventType").value("USER_LOGIN_FAILED"))
                .andExpect(jsonPath("$[0].username").value(username))
                .andExpect(jsonPath("$[0].details.reason").value("BAD_CREDENTIALS"));
    }

    @Test
    void loginRateLimitReturnsTooManyRequests() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "limited_" + UUID.randomUUID().toString().replace("-", "");
        String ip = nextLoginIp();
        String payload = """
                {
                  "username": "%s",
                  "password": "wrong"
                }
                """.formatted(username);

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .cookie(csrf.cookie())
                            .header("X-XSRF-TOKEN", csrf.token())
                            .header(HttpHeaders.USER_AGENT, USER_AGENT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(payload)
                            .with(remoteAddr(ip)))
                    .andExpect(status().isUnauthorized());
        }

        mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload)
                        .with(remoteAddr(ip)))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("RATE_LIMIT_EXCEEDED"))
                .andExpect(jsonPath("$.message").value("Too many requests. Please try again later"));
    }

    @Test
    void loginRateLimitIgnoresForwardedForFromUntrustedRemote() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "xff_untrusted_" + UUID.randomUUID().toString().replace("-", "");
        String ip = nextLoginIp();
        String payload = """
                {
                  "username": "%s",
                  "password": "wrong"
                }
                """.formatted(username);

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .cookie(csrf.cookie())
                            .header("X-XSRF-TOKEN", csrf.token())
                            .header(HttpHeaders.USER_AGENT, USER_AGENT)
                            .header("X-Forwarded-For", "203.0.113.%d".formatted(i + 1))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(payload)
                            .with(remoteAddr(ip)))
                    .andExpect(status().isUnauthorized());
        }

        mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .header("X-Forwarded-For", "203.0.113.99")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload)
                        .with(remoteAddr(ip)))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("RATE_LIMIT_EXCEEDED"));
    }

    @Test
    void loginRateLimitTrustsForwardedForFromTrustedProxy() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "xff_trusted_" + UUID.randomUUID().toString().replace("-", "");
        String payload = """
                {
                  "username": "%s",
                  "password": "wrong"
                }
                """.formatted(username);

        for (int i = 0; i < 6; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .cookie(csrf.cookie())
                            .header("X-XSRF-TOKEN", csrf.token())
                            .header(HttpHeaders.USER_AGENT, USER_AGENT)
                            .header("X-Forwarded-For", "198.51.100.%d".formatted(i + 1))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(payload)
                            .with(remoteAddr("10.0.0.10")))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Test
    void authSessionStoresResolvedClientIpInsteadOfSpoofedForwardedAddress() throws Exception {
        CsrfContext csrf = getCsrfContext();
        String username = "resolved_ip_" + UUID.randomUUID().toString().replace("-", "");
        String payload = objectMapper.writeValueAsString(new RegisterRequest(
                username,
                "Password123!",
                username + "@example.com",
                null
        ));

        MvcResult registerResult = mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .header("X-Forwarded-For", "198.51.100.99, 203.0.113.25")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload)
                        .with(remoteAddr("10.0.0.10")))
                .andExpect(status().isOk())
                .andReturn();

        mockMvc.perform(get("/api/v1/auth/sessions")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + readAccessToken(registerResult)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].ip").value("203.0.113.25"));
    }

    @Test
    void outboxClaimUsesProcessingLeaseAndSeparateFinalMark() {
        Instant now = Instant.now();
        UUID eventId = UUID.randomUUID();
        savePendingOutboxEvent(eventId, now);

        List<OutboxEvent> claimed = outboxEventService.claimPublishable(now);

        org.junit.jupiter.api.Assertions.assertTrue(claimed.stream().anyMatch(event -> event.getId().equals(eventId)));
        OutboxEvent processing = outboxEventRepository.findById(eventId).orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals(OutboxEventStatus.PROCESSING, processing.getStatus());
        org.junit.jupiter.api.Assertions.assertEquals(1, processing.getAttempts());
        org.junit.jupiter.api.Assertions.assertNotNull(processing.getClaimId());
        org.junit.jupiter.api.Assertions.assertTrue(
                !processing.getLastAttemptAt().isBefore(now.minusMillis(1))
                        && !processing.getLastAttemptAt().isAfter(now.plusMillis(1))
        );
        org.junit.jupiter.api.Assertions.assertTrue(processing.getLeaseUntil().isAfter(now));

        org.junit.jupiter.api.Assertions.assertTrue(outboxEventService.markPublished(
                processing.getId(),
                processing.getClaimId(),
                now.plusSeconds(1)
        ));

        OutboxEvent published = outboxEventRepository.findById(eventId).orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals(OutboxEventStatus.PUBLISHED, published.getStatus());
        org.junit.jupiter.api.Assertions.assertNotNull(published.getPublishedAt());
        org.junit.jupiter.api.Assertions.assertNull(published.getClaimId());
        org.junit.jupiter.api.Assertions.assertNull(published.getLeaseUntil());
    }

    @Test
    void staleOutboxClaimCannotOverwriteCurrentClaim() {
        Instant now = Instant.now();
        UUID eventId = UUID.randomUUID();
        savePendingOutboxEvent(eventId, now);

        OutboxEvent firstClaim = findClaim(outboxEventService.claimPublishable(now), eventId);
        Instant reclaimedAt = firstClaim.getLeaseUntil().plusMillis(1);
        OutboxEvent secondClaim = findClaim(outboxEventService.claimPublishable(reclaimedAt), eventId);

        org.junit.jupiter.api.Assertions.assertNotEquals(firstClaim.getClaimId(), secondClaim.getClaimId());
        org.junit.jupiter.api.Assertions.assertEquals(2, secondClaim.getAttempts());
        org.junit.jupiter.api.Assertions.assertFalse(outboxEventService.markPublished(
                eventId,
                firstClaim.getClaimId(),
                reclaimedAt.plusSeconds(1)
        ));

        OutboxEvent stillProcessing = outboxEventRepository.findById(eventId).orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals(OutboxEventStatus.PROCESSING, stillProcessing.getStatus());
        org.junit.jupiter.api.Assertions.assertEquals(secondClaim.getClaimId(), stillProcessing.getClaimId());
        org.junit.jupiter.api.Assertions.assertTrue(outboxEventService.markPublished(
                eventId,
                secondClaim.getClaimId(),
                reclaimedAt.plusSeconds(2)
        ));
    }

    @Test
    void crashedOutboxClaimsBecomeDeadAfterMaximumAttempts() {
        Instant attemptAt = Instant.now();
        UUID eventId = UUID.randomUUID();
        savePendingOutboxEvent(eventId, attemptAt);

        for (int attempt = 1; attempt <= kafkaEventProperties.maxAttempts(); attempt++) {
            OutboxEvent claim = findClaim(outboxEventService.claimPublishable(attemptAt), eventId);
            org.junit.jupiter.api.Assertions.assertEquals(attempt, claim.getAttempts());
            attemptAt = claim.getLeaseUntil().plusMillis(1);
        }

        org.junit.jupiter.api.Assertions.assertTrue(outboxEventService.claimPublishable(attemptAt).stream()
                .noneMatch(event -> event.getId().equals(eventId)));
        OutboxEvent dead = outboxEventRepository.findById(eventId).orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals(OutboxEventStatus.DEAD, dead.getStatus());
        org.junit.jupiter.api.Assertions.assertEquals(kafkaEventProperties.maxAttempts(), dead.getAttempts());
        org.junit.jupiter.api.Assertions.assertNull(dead.getClaimId());
        org.junit.jupiter.api.Assertions.assertNull(dead.getLeaseUntil());
    }

    @Test
    void finalOutboxPublishFailureBecomesDeadImmediately() {
        Instant now = Instant.now();
        UUID eventId = UUID.randomUUID();
        outboxEventRepository.save(OutboxEvent.builder()
                .id(eventId)
                .topic("auth.events")
                .eventKey(eventId.toString())
                .eventType("TEST_EVENT")
                .payloadJson("{}")
                .status(OutboxEventStatus.FAILED)
                .attempts(kafkaEventProperties.maxAttempts() - 1)
                .createdAt(now)
                .nextAttemptAt(now.minusSeconds(1))
                .build());

        OutboxEvent finalClaim = findClaim(outboxEventService.claimPublishable(now), eventId);
        org.junit.jupiter.api.Assertions.assertEquals(kafkaEventProperties.maxAttempts(), finalClaim.getAttempts());
        org.junit.jupiter.api.Assertions.assertTrue(outboxEventService.markFailed(
                eventId,
                finalClaim.getClaimId(),
                "Kafka unavailable",
                now.plusSeconds(30)
        ));

        OutboxEvent dead = outboxEventRepository.findById(eventId).orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals(OutboxEventStatus.DEAD, dead.getStatus());
        org.junit.jupiter.api.Assertions.assertEquals("Kafka unavailable", dead.getLastError());
    }

    private void savePendingOutboxEvent(UUID eventId, Instant now) {
        outboxEventRepository.save(OutboxEvent.builder()
                .id(eventId)
                .topic("auth.events")
                .eventKey(eventId.toString())
                .eventType("TEST_EVENT")
                .payloadJson("{}")
                .status(OutboxEventStatus.PENDING)
                .attempts(0)
                .createdAt(now)
                .nextAttemptAt(now.minusSeconds(1))
                .build());
    }

    private OutboxEvent findClaim(List<OutboxEvent> claimed, UUID eventId) {
        return claimed.stream()
                .filter(event -> event.getId().equals(eventId))
                .findFirst()
                .orElseThrow();
    }

    private CsrfContext getCsrfContext() throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/api/v1/auth/csrf"))
                .andExpect(status().isOk())
                .andReturn();

        Cookie xsrfCookie = csrfResult.getResponse().getCookie("XSRF-TOKEN");
        JsonNode csrfBody = objectMapper.readTree(csrfResult.getResponse().getContentAsString());
        return new CsrfContext(xsrfCookie, csrfBody.get("token").asText());
    }

    private void createAuthClient(String superAdminAccessToken, String clientId, String origin) throws Exception {
        String audience = "audience-" + UUID.randomUUID().toString().replace("-", "");
        String createPayload = """
                {
                  "clientId": "%s",
                  "name": "Origin Test Client",
                  "enabled": true,
                  "accessTokenTtlSeconds": 300,
                  "refreshTokenTtlSeconds": 86400,
                  "tokenAudience": "%s",
                  "allowedOrigins": ["%s"]
                }
                """.formatted(clientId, audience, origin);

        mockMvc.perform(post("/api/v1/admin/auth-clients")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + superAdminAccessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientId").value(clientId))
                .andExpect(jsonPath("$.allowedOrigins[0]").value(origin));
    }

    private String readAccessToken(MvcResult result) throws Exception {
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return body.get("accessToken").asText();
    }

    private MvcResult registerUser(CsrfContext csrf, String username) throws Exception {
        String payload = objectMapper.writeValueAsString(new RegisterRequest(
                username,
                "Password123!",
                username + "@example.com",
                null
        ));

        return mockMvc.perform(post("/api/v1/auth/register")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andReturn();
    }

    private MvcResult loginUser(CsrfContext csrf, String username, String password) throws Exception {
        String payload = """
                {
                  "username": "%s",
                  "password": "%s"
                }
                """.formatted(username, password);

        return mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrf.cookie())
                        .header("X-XSRF-TOKEN", csrf.token())
                        .header(HttpHeaders.USER_AGENT, USER_AGENT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload)
                        .with(remoteAddr(nextLoginIp())))
                .andExpect(status().isOk())
                .andReturn();
    }

    private UUID readUuidClaim(String accessToken, String claimName) throws Exception {
        return UUID.fromString(readTokenPayload(accessToken).get(claimName).asText());
    }

    private String readStringClaim(String accessToken, String claimName) throws Exception {
        return readTokenPayload(accessToken).get(claimName).asText();
    }

    private JsonNode readTokenPayload(String accessToken) throws Exception {
        return objectMapper.readTree(new String(
                java.util.Base64.getUrlDecoder().decode(accessToken.split("\\.")[1]),
                StandardCharsets.UTF_8
        ));
    }

    private RequestPostProcessor remoteAddr(String ip) {
        return request -> {
            request.setRemoteAddr(ip);
            return request;
        };
    }

    private String nextLoginIp() {
        int value = LOGIN_IP_COUNTER.getAndIncrement();
        return "10.20.%d.%d".formatted(value / 250, value % 250 + 1);
    }

    private String issueAccessTokenWithWrongIssuer(String validAccessToken, String issuer) throws Exception {
        return issueAccessToken(validAccessToken, issuer, List.of(AUTH_SERVICE_AUDIENCE, DEFAULT_AUDIENCE));
    }

    private String issueAccessToken(String validAccessToken, String issuer, List<String> audiences) throws Exception {
        JsonNode tokenPayload = readTokenPayload(validAccessToken);

        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(600))
                .subject(tokenPayload.get("sub").asText())
                .audience(audiences)
                .claim("uid", tokenPayload.get("uid").asText())
                .claim("roles", List.of("USER"))
                .claim("sid", tokenPayload.get("sid").asText())
                .claim("client_id", tokenPayload.get("client_id").asText())
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256)
                        .keyId(TEST_JWT_KEY_ID)
                        .build(),
                claims
        )).getTokenValue();
    }

    private void assertAudienceContains(JsonNode tokenPayload, String... expectedAudiences) {
        List<String> audiences = new java.util.ArrayList<>();
        JsonNode audienceClaim = tokenPayload.get("aud");
        if (audienceClaim.isArray()) {
            audienceClaim.forEach(audience -> audiences.add(audience.asText()));
        } else {
            audiences.add(audienceClaim.asText());
        }
        List<String> distinctExpectedAudiences = java.util.Arrays.stream(expectedAudiences)
                .distinct()
                .toList();
        org.junit.jupiter.api.Assertions.assertEquals(distinctExpectedAudiences, audiences);
    }

    private static KeyPair generateTestKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to generate test RSA key pair", e);
        }
    }

    private record CsrfContext(Cookie cookie, String token) {
    }
}
