package com.project.auth_service.rate_limit;

import com.project.auth_service.config.RateLimitProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RateLimitService {
    private final RateLimitProperties properties;
    private final RateLimitBackend backend;
    private final RateLimitAccountKeyHasher accountKeyHasher;

    public RateLimitBackend.Result tryConsume(Scope scope, String key) {
        return backend.tryConsume(List.of(new RateLimitBackend.Request(scope, key, limitFor(scope))));
    }

    public RateLimitBackend.Result tryConsumeLogin(String normalizedAccountIdentifier, String ip) {
        String accountKey = accountKeyHasher.hash(normalizedAccountIdentifier);
        return backend.tryConsume(List.of(
                new RateLimitBackend.Request(Scope.LOGIN_IP, ip, properties.login().ip()),
                new RateLimitBackend.Request(Scope.LOGIN_ACCOUNT, accountKey, properties.login().account()),
                new RateLimitBackend.Request(Scope.LOGIN_ACCOUNT_IP, accountKey + ":" + ip, properties.login().accountIp())
        ));
    }

    private RateLimitProperties.Limit limitFor(Scope scope) {
        return switch (scope) {
            case LOGIN_IP -> properties.login().ip();
            case LOGIN_ACCOUNT -> properties.login().account();
            case LOGIN_ACCOUNT_IP -> properties.login().accountIp();
            case REGISTER -> properties.register();
            case REFRESH -> properties.refresh();
            case PASSWORD_CHANGE -> properties.passwordChange();
            case ADMIN -> properties.admin();
        };
    }

    public enum Scope {
        LOGIN_IP("login:ip"),
        LOGIN_ACCOUNT("login:account"),
        LOGIN_ACCOUNT_IP("login:account-ip"),
        REGISTER("register"),
        REFRESH("refresh"),
        PASSWORD_CHANGE("password-change"),
        ADMIN("admin");

        private final String keyPrefix;

        Scope(String keyPrefix) {
            this.keyPrefix = keyPrefix;
        }

        public String keyPrefix() {
            return keyPrefix;
        }

        public boolean isLogin() {
            return this == LOGIN_IP || this == LOGIN_ACCOUNT || this == LOGIN_ACCOUNT_IP;
        }
    }
}
