package com.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.configs.dto.AuthRequest;
import com.security.configs.entity.UserInfo;
import com.security.configs.service.JwtService;
import com.security.repository.JwtExampleRepository;

@RestController
@RequestMapping(value="/jwt")
public class JwtExampleController {
	

	@Autowired
	JwtExampleRepository jwtRepo;
	
	@Autowired
	PasswordEncoder passwordEncoder;
	
	@Autowired
	JwtService jwtService;
	
	@Autowired
	AuthenticationManager authManager;
	
	
	@GetMapping(value="/get")
	public String getMessage() {
		return "hello everyone";
	}
	
	@GetMapping(value="/getAdmin")
	@PreAuthorize("hasAuthority('ROLE_ADMIN')")
	public String getAdmin() {
		return "hello admin";
	}
	
	@GetMapping(value="/getUser")
	@PreAuthorize("hasAuthority('ROLE_USER')")
	public String getUser() {
		return "hello user";
	}
	
	@PostMapping(value="/addUser")
	public UserInfo addUser(@RequestBody UserInfo user) {
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		 return jwtRepo.save(user);
	}
	
	@PostMapping(value="/authenticate")
	public String createToken(@RequestBody AuthRequest authRequest) throws Exception {
		Authentication authentication= authManager
				.authenticate(new UsernamePasswordAuthenticationToken(authRequest
						.getUsername(), authRequest.getPassword()));
		if(authentication.isAuthenticated()) {
		
		return jwtService.generatedToken(authRequest.getUsername());
		}
		else {
			throw new UsernameNotFoundException("invalid user!");
		}
		
	}
	
	
	
//	@PostMapping(value="/authenticate")
//	public String autheniticateAndGetToken(@RequestBody AuthRequest authRequest) {
//		Authentication authenticator= authManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
//		if(authenticator.isAuthenticated()) {
//			return jwtService.generateToken(authRequest.getUsername());
//		}
//		else {
//			throw new UsernameNotFoundException("invalid user request!");
//		}
//
//	
//	}



}
