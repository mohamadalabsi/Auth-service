package com.pm.authservice.controller;


import com.pm.authservice.dto.LoginRequestDTO;
import com.pm.authservice.dto.LoginResponseDTO;
import com.pm.authservice.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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

    @Operation(summary = "Validate token")
    @GetMapping("/validate")
    public ResponseEntity<String> validateToken(
            @RequestHeader("Authorization") String authHeader) { //any request that we to
        // validate endpoint , spring will get the Authorization header from the request Header and
        // pass it to this method as a parameter

//        we will have headers and one of them will be the Authorization header and the value of
//        that header will be  bearer like this  Authorization: Bearer <token>

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return authService.validateToken(authHeader.substring(7))? // we will remove the "Bearer " part from the header value to get the actual token
                ResponseEntity.ok("Token is valid")
                : ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();


    }
}
