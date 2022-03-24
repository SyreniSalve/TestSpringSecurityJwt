package com.example.TestSpringSecurityJwt.repository;

import com.example.TestSpringSecurityJwt.models.ERole;
import com.example.TestSpringSecurityJwt.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.stereotype.Repository;

import java.util.Optional;

//This repository also extends JpaRepository and provides a finder method.
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(ERole name);
}
