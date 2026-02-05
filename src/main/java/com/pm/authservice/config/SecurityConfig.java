package com.pm.authservice.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
                .csrf(AbstractHttpConfigurer::disable);
//        so here first line it tells spring security to allow all requests without adding
//        any security checks , we don't need to block requests in auth service level as the only
//        request we are going to receive is from api gateway which we control and we do not
//        expose our auth service to the internet directly so it reduces the risk of receiving
//        any bad requests from any bad actors
//        the second line disables cross site request forgery stuff which is not needed

        return http.build();
// this is the first step in setting up spring security in our auth service
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
//  we have to have a bean here so we can use this password encoder in our auth service to hash
//  the passwords and to check if the password , it is different than other classes and interfaces because it is a bean that we need to use in other classes so we need to define it here and spring will inject it wherever we need it
    }

}
