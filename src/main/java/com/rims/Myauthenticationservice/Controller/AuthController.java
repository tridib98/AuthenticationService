package com.rims.Myauthenticationservice.Controller;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import com.rims.Myauthenticationservice.Security.JwtService;
import com.rims.Myauthenticationservice.dto.AuthRequest;;


@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final UserDetailsService uds;

    public AuthController(AuthenticationManager authManager, JwtService jwtService, UserDetailsService uds) {
        this.authManager = authManager;
        this.jwtService = jwtService;
        this.uds = uds;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try {
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
            System.out.println("In login section");
            UserDetails userDetails = uds.loadUserByUsername(request.getUsername());
            String token = jwtService.generateToken(userDetails);

            // return token and basic user info
            return ResponseEntity.ok(Map.of(
                    "token", token,
                    "username", userDetails.getUsername(),
                    "authorities", userDetails.getAuthorities()
            ));
        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
        }
    }
}




