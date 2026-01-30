package com.pm.authservice.service;

import com.pm.authservice.dto.LoginRequestDTO;
import com.pm.authservice.model.User;
import jakarta.validation.Valid;
import org.springframework.stereotype.Service;

import java.util.Optional;


@Service
public class AuthService {


    private final UserService userService;
    public AuthService(UserService userService) {
        this.userService = userService;
    }

    public Optional<String> authenticate(LoginRequestDTO loginRequestDTO) {

//        it makes our code cleaner  and more extensible so in future if we want to find a user
//        by email , all we need to do is to call the userService.findByEmail method
//         now we need to check it the password is valid and if yes we will generate a token

//        !!! important
        Optional<String> token= userService.findByEmail(loginRequestDTO.getEmail())
                .filter(u -> passwordEncoder.matches(loginRequestDTO.getPassword(), u.getPassword()))
                .map(u ->jwtUtil.generateToken(u.getEmail(), u.getRole()));


        return token;


    }
}
