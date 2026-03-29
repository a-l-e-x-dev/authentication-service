package com.innowise.authentication_service.repository;

import com.innowise.authentication_service.entities.AuthCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthCredentialRepository extends JpaRepository<AuthCredential, Long> {

    Optional<AuthCredential> findByLogin(String login);

    Optional<AuthCredential> findByRefreshToken(String refreshToken);
}