package com.project.auth_service.repository;

import com.project.auth_service.entity.RefreshToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long>, JpaSpecificationExecutor<RefreshToken> {
    boolean existsByUserIdAndClientIdAndSessionIdAndRevokedFalseAndExpiresAtAfter(
            UUID userId,
            String clientId,
            String sessionId,
            Instant now
    );

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
        update RefreshToken t
        set t.revoked = true,
            t.revokedAt = :now
        where t.userId = :userId
        and t.revoked = false
        """)
    int revokeAllActiveByUserId(@Param("userId") UUID userId,
                                @Param("now") Instant now);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
        update RefreshToken t
        set t.revoked = true,
            t.revokedAt = :now
        where t.userId = :userId
        and t.sessionId = :sessionId
        and t.revoked = false
        """)
    int revokeAllActiveByUserIdAndSessionId(@Param("userId") UUID userId,
                                            @Param("sessionId") String sessionId,
                                            @Param("now") Instant now);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
        update RefreshToken t
        set t.revoked = true,
            t.revokedAt = :now
        where t.userId = :userId
        and t.sessionId <> :sessionId
        and t.revoked = false
        """)
    int revokeAllActiveByUserIdExceptSessionId(@Param("userId") UUID userId,
                                               @Param("sessionId") String sessionId,
                                               @Param("now") Instant now);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from RefreshToken t where t.tokenHash = :hash")
    Optional<RefreshToken> findByTokenHashForUpdate(@Param("hash") String hash);

    List<RefreshToken> findAllByUserIdAndRevokedFalse(UUID userId);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
        update RefreshToken t
           set t.rotationAttemptId = null,
               t.rotationResultTokenCipher = null,
               t.rotationResultExpiresAt = null
         where t.rotationResultExpiresAt is not null
           and t.rotationResultExpiresAt < :now
    """)
    int clearExpiredRotationReplayPayloads(@Param("now") Instant now);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from RefreshToken t where t.expiresAt < :cutoff")
    int deleteExpiredBefore(@Param("cutoff") Instant cutoff);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from RefreshToken t where t.tokenHash = :hash")
    int deleteByTokenHash(@Param("hash") String hash);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from RefreshToken t where t.userId = :userId")
    int deleteAllByUserId(@Param("userId") UUID userId);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from RefreshToken t where t.userId = :userId and t.sessionId = :sessionId")
    int deleteAllByUserIdAndSessionId(@Param("userId") UUID userId, @Param("sessionId") String sessionId);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from RefreshToken t where t.userId = :userId and t.sessionId <> :sessionId")
    int deleteAllByUserIdExceptSessionId(@Param("userId") UUID userId, @Param("sessionId") String sessionId);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
        update RefreshToken t
           set t.compromisedAt = :now,
               t.compromisedReason = :reason
         where t.userId = :userId
           and t.sessionId = :sessionId
           and t.compromisedAt is null
    """)
    int markSessionCompromisedOnce(@Param("userId") UUID userId,
                                   @Param("sessionId") String sessionId,
                                   @Param("now") Instant now,
                                   @Param("reason") String reason);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
        update RefreshToken t
           set t.compromisedAt = :now,
               t.compromisedReason = :reason
         where t.userId = :userId
           and t.compromisedAt is null
    """)
    int markAllSessionsCompromisedOnce(@Param("userId") UUID userId,
                                   @Param("now") Instant now,
                                   @Param("reason") String reason);
}
