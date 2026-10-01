package org.example.identityservice.models.services.impl;

import lombok.RequiredArgsConstructor;
import org.example.identityservice.exceptions.BadRequestException;
import org.example.identityservice.exceptions.NotFoundException;
import org.example.identityservice.models.constants.RoleName;
import org.example.identityservice.models.dto.req.LoginReq;
import org.example.identityservice.models.dto.req.RefreshReq;
import org.example.identityservice.models.dto.req.RegisterReq;
import org.example.identityservice.models.dto.res.JwtRes;
import org.example.identityservice.models.entities.RefreshToken;
import org.example.identityservice.models.entities.Role;
import org.example.identityservice.models.entities.User;
import org.example.identityservice.models.repositories.RoleRepository;
import org.example.identityservice.models.repositories.UserRepository;
import org.example.identityservice.models.services.AuthService;
import org.example.identityservice.models.services.RefreshTokenService;
import org.example.identityservice.security.jwt.JwtUtils;
import org.example.identityservice.security.principal.MyUserDetails;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuthenticationManager manager;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final StringRedisTemplate redisTemplate;

    @Override
    public void register(RegisterReq req) {
        Set<Role> roles = new HashSet<>();
        roles.add(roleRepository.findByRoleName(RoleName.ROLE_USER)
                .orElseThrow(() -> new NotFoundException("Role not found")));

        User user = User.builder()
                .fullName(req.fullName())
                .username(req.username())
                .password(encoder.encode(req.password()))
                .roles(roles)
                .build();
        userRepository.save(user);
    }

    @Override
    public JwtRes login(LoginReq req) {
        Authentication authentication;
        try {
            authentication = manager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.username(), req.password()));
        } catch (AuthenticationException e) {
            throw new BadRequestException("Username or password is incorrect");
        }

        MyUserDetails userDetails = (MyUserDetails) authentication.getPrincipal();
        User user = userDetails.getUser();

        String accessToken = jwtUtils.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return new JwtRes(accessToken, refreshToken.getToken(), "Bearer", roles);
    }

    @Override
    @Transactional
    public JwtRes refresh(RefreshReq req) {
        // 1. Find by token
        RefreshToken token = refreshTokenService.getByToken(req.refreshToken()); // will add method
        // 2. Verify expiration
        refreshTokenService.verifyExpiration(token);
        // 3. Rotation: delete old
        refreshTokenService.deleteByToken(req.refreshToken());
        // 4. New access
        String accessToken = jwtUtils.generateAccessToken(token.getUser());
        // 5. New refresh
        RefreshToken newRefresh = refreshTokenService.createRefreshToken(token.getUser().getId());
        return new JwtRes(accessToken, newRefresh.getToken(), "Bearer", null);
    }

    @Override
    public void logout(String token) {
        // 1. Extract jti and exp
        String jti = jwtUtils.extractJti(token);
        Date exp = jwtUtils.extractExpiration(token);
        // 2. TTL = exp - now
        long ttlMillis = exp.getTime() - System.currentTimeMillis();
        if (ttlMillis <= 0) {
            return; // already expired
        }
        // 3. Save to Redis blacklist:{jti}
        String key = "blacklist:" + jti;
        redisTemplate.opsForValue().set(key, "revoked", ttlMillis, TimeUnit.MILLISECONDS);
        // 4. Optional: delete refresh tokens of user - skip for simplicity or implement if needed
    }
}
