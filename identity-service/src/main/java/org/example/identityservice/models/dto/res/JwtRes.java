package org.example.identityservice.models.dto.res;

import java.util.List;

public record JwtRes(
        String accessToken,
        String refreshToken,
        String type,
        List<String> roles
) {
}
