package com.example.testsecurity.repository;

import com.example.testsecurity.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    boolean existsByUsername(String password);

    UserEntity findByUsername(String username);
}
