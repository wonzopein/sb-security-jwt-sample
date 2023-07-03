package com.wonzopein.sbsecurityjwtsample.infrastructure.rest.api.auth;

import com.wonzopein.sbsecurityjwtsample.infrastructure.persistance.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthRepository extends JpaRepository<User, String> {
}
