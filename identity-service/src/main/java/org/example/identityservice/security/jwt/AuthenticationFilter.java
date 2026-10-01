package org.example.identityservice.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class AuthenticationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // nhận đc 2 thông tin: X-Auth-UserId v X-Auth-Roles
        String xAuthUserId = request.getHeader("X-Auth-UserId");
        String xAuthRoles = request.getHeader("X-Auth-Roles");
        System.out.println("xAuthUserId: " + xAuthUserId);
        System.out.println("xAuthRoles: " + xAuthRoles); // "[ROLE_ADMIN]"

        // tạo ra được 1 đối tượng authentication và lưu vào security context
        if(StringUtils.hasText(xAuthUserId)){
            List<GrantedAuthority> authorities = Collections.emptyList(); // danh sách rỗng
            if(StringUtils.hasText(xAuthRoles)){
                authorities = Arrays.stream(xAuthRoles.replace("[","").replace("]","").split(","))
                        .map(String::trim)
                        .filter(role-> !role.isEmpty())
                        .map(role-> role.startsWith("ROLE_")?role: "ROLE_"+role)
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
                System.out.println(authorities.toString());

                Authentication auth = new UsernamePasswordAuthenticationToken(xAuthUserId, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }
        filterChain.doFilter(request, response);
    }
}
