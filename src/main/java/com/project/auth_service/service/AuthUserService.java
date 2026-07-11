package com.project.auth_service.service;

import com.project.auth_service.entity.User;
import com.project.auth_service.repository.UserRepository;
import com.project.auth_service.entity.UserRoleEntity;
import com.project.auth_service.entity.UserRoleId;
import com.project.auth_service.enums.Role;
import com.project.auth_service.exceptions.EmailAlreadyExistsException;
import com.project.auth_service.exceptions.UserNotFoundException;
import com.project.auth_service.exceptions.UsernameAlreadyExistsException;
import com.project.auth_service.repository.UserRoleRepository;
import com.project.auth_service.service.dto.AuthUser;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthUserService {
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;

    public Optional<AuthUser> findByUsername(String username) {
        return userRepository.findByUsername(username)
                .map(this::toAuthUser);
    }

    public Optional<AuthUser> findById(UUID userId) {
        return userRepository.findById(userId)
                .map(this::toAuthUser);
    }

    @Transactional
    public User findByIdForUpdate(UUID userId) {
        return userRepository.findByIdForUpdate(userId)
                .orElseThrow(UserNotFoundException::new);
    }

    @Transactional
    public AuthUser registerLocalUser(String username, String email, String passwordHash) {
        return registerLocalUser(username, email, passwordHash, List.of(Role.USER));
    }

    @Transactional
    public AuthUser registerLocalUser(String username, String email, String passwordHash, List<Role> roles) {
        if (userRepository.existsByUsername(username)) {
            throw new UsernameAlreadyExistsException();
        }
        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyExistsException();
        }

        try {
            User user = userRepository.save(User.builder()
                    .username(username)
                    .email(email)
                    .passwordHash(passwordHash)
                    .createdAt(Instant.now())
                    .build());

            roles.stream()
                    .distinct()
                    .map(role -> new UserRoleEntity(new UserRoleId(user.getId(), role)))
                    .forEach(userRoleRepository::save);

            return new AuthUser(user.getId(), user.getUsername(), user.getPasswordHash(), roles.stream().distinct().toList());
        } catch (DataIntegrityViolationException e) {
            if (userRepository.existsByUsername(username)) {
                throw new UsernameAlreadyExistsException();
            }
            if (userRepository.existsByEmail(email)) {
                throw new EmailAlreadyExistsException();
            }
            throw e;
        }
    }

    private AuthUser toAuthUser(User user) {
        List<Role> roles = userRoleRepository.findRolesByUserId(user.getId());
        return new AuthUser(user.getId(), user.getUsername(), user.getPasswordHash(), roles);
    }
}
