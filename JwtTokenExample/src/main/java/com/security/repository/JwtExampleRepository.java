package com.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.security.configs.entity.UserInfo;


public interface JwtExampleRepository extends JpaRepository<UserInfo, Integer>{

	Optional<UserInfo> findByName(String username);

}
