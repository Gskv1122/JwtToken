package com.security.configs.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtService {
	
	private static final String SECRET="tTfzhMHenxvChd1ARfVNZUSmuGLlvZgi7nl4Tt6KPNCQMnSFp/BwEOm/fObKgfu8PJxKVp4IYdV56eGoU/rc44ze2Ljap0+oOGNmMgTEf3hJEO7mOJZqCvAQR7cF5HtVg2OLaGfLLLMjFNNaXuV3bpixgSoqQ7MIeyvlf/4sqgGKEkWDr9YWeXIaY06+X8ITavk6JVyu9gD0jd/4H/nf03a78OyzKy2fjIGpqWLKA0H/fShz4GHvOKq+iTWJ1I6hzpuQoSNEnyxqGlD+uWjXOauNfy0ANbDKZetHACiRAQ2zkdqLR6lHzcTvcaJD5vaJfnrA7nJyf8b8iJI82bPBropS1IdFjr+Ce8u2fxYfY0k=";

	public String extractUserName(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}

	private Claims extractAllClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token).getBody();
	}

	private Boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = extractUserName(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}


	public String generatedToken(String username) {
		Map<String, Object>claims=new HashMap<>();
		return createToken(claims,username);
	}

	private String createToken(Map<String, Object> claims, String username) {
		return Jwts.builder()
				.setClaims(claims)
				.setSubject(username)
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+1000*60*5))
				.signWith(getSignKey(),SignatureAlgorithm.HS256).compact();
	}

	private Key getSignKey() {
		byte[] token=Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(token);
	}
	
	

}
