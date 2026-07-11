package com.project.auth_service.rate_limit;

import com.project.auth_service.config.RateLimitProperties;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RateLimitServiceTests {

    @Test
    void accountBucketRejectsSameAccountAcrossDifferentIps() {
        RateLimitProperties properties = properties(100, 2, 100);
        InMemoryRateLimitBackend backend = new InMemoryRateLimitBackend(properties);
        RateLimitService service = new RateLimitService(
                properties,
                backend,
                new RateLimitAccountKeyHasher(properties)
        );

        assertTrue(service.tryConsumeLogin("alice", "203.0.113.1").consumed());
        assertTrue(service.tryConsumeLogin("alice", "203.0.113.2").consumed());

        RateLimitBackend.Result rejected = service.tryConsumeLogin("alice", "203.0.113.3");
        assertFalse(rejected.consumed());
        assertEquals(RateLimitService.Scope.LOGIN_ACCOUNT, rejected.rejectedScope());
    }

    @Test
    void accountHasherIsStableAndDoesNotExposeAccountIdentifier() {
        RateLimitProperties properties = properties(100, 100, 100);
        RateLimitAccountKeyHasher hasher = new RateLimitAccountKeyHasher(properties);

        String first = hasher.hash("alice@example.com");
        String second = hasher.hash("alice@example.com");

        assertEquals(first, second);
        assertNotEquals("alice@example.com", first);
        assertFalse(first.contains("alice"));
        assertEquals(64, first.length());
    }

    private RateLimitProperties properties(long ipCapacity, long accountCapacity, long accountIpCapacity) {
        return new RateLimitProperties(
                new RateLimitProperties.Login(
                        limit(ipCapacity),
                        limit(accountCapacity),
                        limit(accountIpCapacity),
                        "test-rate-limit-account-key-secret-0123456789"
                ),
                limit(100),
                limit(100),
                limit(100),
                limit(100),
                RateLimitProperties.Backend.IN_MEMORY,
                "test:rate-limit",
                List.of()
        );
    }

    private RateLimitProperties.Limit limit(long capacity) {
        return new RateLimitProperties.Limit(capacity, Duration.ofMinutes(10));
    }
}
