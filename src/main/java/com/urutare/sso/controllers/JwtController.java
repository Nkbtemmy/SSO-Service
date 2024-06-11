package com.urutare.sso.controllers;

import com.urutare.sso.dto.TokenRequest;
import com.urutare.sso.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
public class JwtController {

    private final JwtService jwtService;

    @Autowired
    public JwtController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @PostMapping("/token")
    public ResponseEntity<String> generateToken(@RequestBody TokenRequest tokenRequest) {
        try {
            String token = jwtService.generateToken(tokenRequest.getSubject());
            return ResponseEntity.ok(token);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error generating token: " + e.getMessage());
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<String> verifyToken(@RequestBody String token) {
        try {

            return ResponseEntity.ok( jwtService.getTokenPayload(token));
        } catch (Exception e) {
            return ResponseEntity.ok("false");
        }
    }


}
