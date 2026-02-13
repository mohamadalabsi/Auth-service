package com.pm.authservice.controller;


import com.pm.authservice.dto.LoginRequestDTO;
import com.pm.authservice.dto.LoginResponseDTO;
import com.pm.authservice.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @Operation(summary = "Generate token on user login")
    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO>  login(@RequestBody @Valid LoginRequestDTO loginRequestDTO) {

        Optional<String> tokenOptional = authService.authenticate(loginRequestDTO); //if the
        // token is not valid , it will return an empty optional , so it depends on the email and password

        if (tokenOptional.isEmpty()){
            return ResponseEntity.status(401).build(); // Unauthorized
        }

        String token = tokenOptional.get();
        return ResponseEntity.ok(new LoginResponseDTO(token));


    }


//    now we want to validate the token that we generated in the login method , so we can use it
//    to access other endpoints in the application and then we can integrating auth service with
//    api gateway
}
