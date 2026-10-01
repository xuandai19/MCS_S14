package org.example.identityservice.controllers;

import lombok.RequiredArgsConstructor;
import org.example.identityservice.models.dto.req.LoginReq;
import org.example.identityservice.models.dto.req.RefreshReq;
import org.example.identityservice.models.dto.req.RegisterReq;
import org.example.identityservice.models.services.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterReq req) {
        authService.register(req);
        return ResponseEntity.status(HttpStatus.CREATED).body("Register Successfully");
    }

    @GetMapping("/test")
    @PreAuthorize("hasRole('ADMIN')")
    public String test() {
        return "Bạn đang truy cập với quyền admin";
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshReq refreshReq) {
        return ResponseEntity.ok(authService.refresh(refreshReq));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req) {
        return ResponseEntity.ok(authService.login(req));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            authService.logout(token);
            return ResponseEntity.ok("Logout successful. Token blacklisted.");
        }
        return ResponseEntity.badRequest().body("Missing or invalid Authorization header");
    }
}
