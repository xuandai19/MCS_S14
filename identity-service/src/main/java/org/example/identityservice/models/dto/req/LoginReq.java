package org.example.identityservice.models.dto.req;

public record LoginReq(
        String username,
        String password
) {
}
