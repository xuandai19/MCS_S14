package org.example.identityservice.models.services;

import org.example.identityservice.models.dto.req.LoginReq;
import org.example.identityservice.models.dto.req.RefreshReq;
import org.example.identityservice.models.dto.req.RegisterReq;
import org.example.identityservice.models.dto.res.JwtRes;

public interface AuthService {

    void register(RegisterReq req);

    JwtRes login(LoginReq req);

    JwtRes refresh(RefreshReq req);

    void logout(String token);
}
