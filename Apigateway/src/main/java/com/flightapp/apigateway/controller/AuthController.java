package com.flightapp.apigateway.controller;

import com.flightapp.apigateway.model.User;
import com.flightapp.apigateway.repository.UserRepository;
import com.flightapp.apigateway.security.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Set;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @PostMapping("/signup")
    public Mono<ResponseEntity<String>> register(@RequestBody User user) {

        return userRepository.existsByUsername(user.getUsername())
                .flatMap(exists -> {
                    if (exists) {
                        return Mono.just(ResponseEntity.badRequest().body("Username already exists"));
                    }

                    user.setPassword(encoder.encode(user.getPassword()));
                    user.setRoles(Set.of("ROLE_USER"));

                    return userRepository.save(user)
                            .map(saved -> ResponseEntity.ok("User registered successfully"));
                });
    }

    @PostMapping("/signin")
    public Mono<ResponseEntity<String>> login(@RequestBody User user) {

        return userRepository.findByUsername(user.getUsername())
                .flatMap(dbUser -> {

                    // ✅ THIS LINE WAS MISSING IN YOUR CODE
                    if (!encoder.matches(user.getPassword(), dbUser.getPassword())) {
                        return Mono.just(
                                ResponseEntity.status(401).body("Invalid credentials")
                        );
                    }

                    String token = jwtUtils.generateJwt(dbUser.getUsername());

                    return Mono.just(
                            ResponseEntity.ok()
                                    .header("Authorization", "Bearer " + token)
                                    .body("Login successful")
                    );
                })
                .switchIfEmpty(
                        Mono.just(
                                ResponseEntity.status(401).body("User not found")
                        )
                );
    }




    @PostMapping("/signout")
    public Mono<ResponseEntity<String>> logout() {
        return Mono.just(ResponseEntity.ok("Logged out successfully"));
    }
}
