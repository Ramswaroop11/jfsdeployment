package com;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthController(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(
            @RequestBody User user) {

        if (userRepository.existsByEmail(user.getEmail())) {

            return ResponseEntity
                    .badRequest()
                    .body("Email already registered");
        }

        user.setPassword(
                passwordEncoder.encode(
                        user.getPassword()
                )
        );

        userRepository.save(user);

        return ResponseEntity.ok(
                "Registration successful"
        );
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody User user) {

        User existingUser =
                userRepository
                        .findByEmail(user.getEmail())
                        .orElse(null);

        if (existingUser == null ||
                !passwordEncoder.matches(
                        user.getPassword(),
                        existingUser.getPassword()
                )) {

            return ResponseEntity
                    .status(401)
                    .body("Invalid email or password");
        }

        String token =
                jwtService.generateToken(
                        existingUser.getEmail()
                );

        return ResponseEntity.ok(
                Map.of(
                        "token", token,
                        "name", existingUser.getName(),
                        "email", existingUser.getEmail()
                )
        );
    }

    @GetMapping("/home")
    public ResponseEntity<?> home(
            Authentication authentication) {

        return ResponseEntity.ok(
                Map.of(
                        "message",
                        "Welcome to Home!",
                        "email",
                        authentication.getName()
                )
        );
    }
}
