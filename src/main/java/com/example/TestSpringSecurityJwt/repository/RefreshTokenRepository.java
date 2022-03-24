package com.example.TestSpringSecurityJwt.repository;

import com.example.TestSpringSecurityJwt.models.RefreshToken;
import com.example.TestSpringSecurityJwt.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    @Override
    Optional<RefreshToken> findById(Long id);
    Optional<RefreshToken> findByToken(String token);
    int deleteByUser(User user);
}
