package com.project.auth_service.rate_limit;

import com.project.auth_service.config.RateLimitProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ClientIpResolverTests {

    @Test
    void ignoresForwardedForFromUntrustedRemote() {
        ClientIpResolver resolver = new ClientIpResolver(properties(List.of("10.0.0.0/8")));
        MockHttpServletRequest request = request("203.0.113.10", "198.51.100.25");

        assertEquals("203.0.113.10", resolver.resolve(request));
    }

    @Test
    void resolvesFirstUntrustedAddressFromRightAndIgnoresSpoofedLeftmostAddress() {
        ClientIpResolver resolver = new ClientIpResolver(properties(List.of("10.0.0.0/8")));
        MockHttpServletRequest request = request(
                "10.0.0.10",
                "198.51.100.99, 203.0.113.25, 10.0.0.20"
        );

        assertEquals("203.0.113.25", resolver.resolve(request));
    }

    @Test
    void invalidForwardedChainFailsClosedToRemoteAddress() {
        ClientIpResolver resolver = new ClientIpResolver(properties(List.of("10.0.0.0/8")));
        MockHttpServletRequest request = request("10.0.0.10", "not-an-ip");

        assertEquals("10.0.0.10", resolver.resolve(request));
    }

    @Test
    void excessivelyLongForwardedChainFailsClosedToRemoteAddress() {
        ClientIpResolver resolver = new ClientIpResolver(properties(List.of("10.0.0.0/8")));
        MockHttpServletRequest request = request(
                "10.0.0.10",
                "192.0.2.1,192.0.2.2,192.0.2.3,192.0.2.4,192.0.2.5,192.0.2.6,"
                        + "192.0.2.7,192.0.2.8,192.0.2.9,192.0.2.10,192.0.2.11"
        );

        assertEquals("10.0.0.10", resolver.resolve(request));
    }

    @Test
    void invalidTrustedProxyConfigurationFailsAtStartup() {
        assertThrows(IllegalStateException.class,
                () -> new ClientIpResolver(properties(List.of("trusted-proxy.example.com"))));
    }

    private MockHttpServletRequest request(String remoteAddress, String forwardedFor) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(remoteAddress);
        request.addHeader("X-Forwarded-For", forwardedFor);
        return request;
    }

    private RateLimitProperties properties(List<String> trustedProxies) {
        RateLimitProperties.Limit limit = new RateLimitProperties.Limit(10, Duration.ofMinutes(1));
        return new RateLimitProperties(
                new RateLimitProperties.Login(
                        limit,
                        limit,
                        limit,
                        "test-rate-limit-account-key-secret-0123456789"
                ),
                limit,
                limit,
                limit,
                limit,
                RateLimitProperties.Backend.IN_MEMORY,
                "test:rate-limit",
                trustedProxies
        );
    }
}
