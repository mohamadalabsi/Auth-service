package com.pm.authservice.service;

import com.pm.authservice.dto.LoginRequestDTO;
import com.pm.authservice.model.User;
import com.pm.authservice.util.JwtUtil;
import jakarta.validation.Valid;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;


@Service
public class AuthService {


    private final UserService userService;
    private final PasswordEncoder passwordEncoder; // it is class variable and spring will inject
    // it and make an object of it and assign it to this variable
    private final JwtUtil jwtUtil ;

    public AuthService(UserService userService, PasswordEncoder passwordEncoder , JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    public Optional<String> authenticate(LoginRequestDTO loginRequestDTO) {

//        it makes our code cleaner  and more extensible so in future if we want to find a user
//        by email , all we need to do is to call the userService.findByEmail method
//         now we need to check it the password is valid and if yes we will generate a token

//        !!! important
        Optional<String> token= userService.findByEmail(loginRequestDTO.getEmail())
                .filter(u -> passwordEncoder.matches(loginRequestDTO.getPassword(), u.getPassword()))
                .map(u ->jwtUtil.generateToken(u.getEmail(), u.getRole()));
//  so what will happen here is that if the user is found by email , then we will check if the password
//  matches the hashed password in the database using the passwordEncoder.matches method
//  if the password matches , then we will generate a token using the jwtUtil.generateToken method
//  and we will return the token wrapped in an Optional
//  if the user is not found or the password does not match , then we will return an empty Optional

        return token;

// so we generated the token , now we have to validate it , so the user can use it to access
// other endpoints in the application
    }

    public boolean validateToken(String token) {
        try {
             jwtUtil.validateToken(token); // if valid then it will return true and if not valid
            // it will throw an exception and we will catch it down
            return true;
        } catch (Exception e) {
            return false; // if there is any exception , then the token is not valid and return
            // false
        }
    }
}
