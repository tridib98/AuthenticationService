package com.rims.Myauthenticationservice.Service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

import com.rims.Myauthenticationservice.Entity.User;
import com.rims.Myauthenticationservice.Repository.UserRepository;

import java.util.Collections;

@Service
public class MyUserDetailsService implements UserDetailsService {

    private final UserRepository repo;

    public MyUserDetailsService(UserRepository repo) {
        this.repo = repo;
    }

    @Override
public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User u = repo.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

    // Directly map enum to Spring Security authority
    String authority = "ROLE_" + u.getRole().name(); // e.g., ROLE_ADMIN, ROLE_VIEWER, ROLE_REGULATORY_OFFICER

    return org.springframework.security.core.userdetails.User
            .withUsername(u.getUsername())
            .password(u.getPassword())
            .authorities(new SimpleGrantedAuthority(authority))
            .accountExpired(false)
            .accountLocked(false)
            .credentialsExpired(false)
            .disabled(false)
            .build();
}

}

