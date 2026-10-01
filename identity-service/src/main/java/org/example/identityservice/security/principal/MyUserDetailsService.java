package org.example.identityservice.security.principal;

import lombok.RequiredArgsConstructor;
import org.example.identityservice.models.entities.User;
import org.example.identityservice.models.repositories.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        return MyUserDetails.builder()
                .user(user)
                .authorities(
                        user.getRoles().stream()
                                .map(
                                        r -> new SimpleGrantedAuthority(r.getRoleName().name()))
                                .toList()
                )
                .build();
    }
}
