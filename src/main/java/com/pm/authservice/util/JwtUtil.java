package com.pm.authservice.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Component // to make it a spring bean and spring inject it wherever we need it
public class JwtUtil {
//    here to generate a JWT token
//    they are secure because they can only verified using a secret key and stored securely on
//    the server side

    private final Key secretKey;


    public JwtUtil(@Value("${jwt.secret}") String secret) { // injecting secretKey from env variable
//        we don't want to store the secret key as text in the code , it will be a security risk
        byte[] keyBytes = Base64.getDecoder()
                .decode(secret.getBytes(StandardCharsets.UTF_8)); // converting the secret string to byte array
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);

//
    }

    public String generateToken(String email, String role) {
        return Jwts.builder()
                .subject(email) // store email as subject to the person who want to login
                .claim("role", role)
                .issuedAt(new Date()) // it will be stored in the token
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 *60 * 10)) // 10 hours expiration
                .signWith(secretKey) // encode this token using the secret key
                .compact(); // it will take all these properties and going to create a string and
        // going to assign it using the secret key , and squish everything down into nice single
        // string that will form our JWT token
    }
}
