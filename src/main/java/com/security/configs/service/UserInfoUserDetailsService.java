package com.security.configs.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.security.configs.entity.UserInfo;
import com.security.configs.entity.UserInfoUserDetails;
import com.security.repository.JwtExampleRepository;

@Service
public class UserInfoUserDetailsService implements UserDetailsService{

	@Autowired
	JwtExampleRepository sr;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<UserInfo>userInfo=sr.findByName(username);
		
		return userInfo.map(i->new UserInfoUserDetails(i))
				.orElseThrow(()->new UsernameNotFoundException("user is not found "+username));
		
		
	}
}
