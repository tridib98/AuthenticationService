package com.rims.Myauthenticationservice.util;


import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.rims.Myauthenticationservice.Entity.Role;
import com.rims.Myauthenticationservice.Entity.User;
import com.rims.Myauthenticationservice.Repository.UserRepository;

@Configuration
public class DataLoader implements CommandLineRunner {

    private final UserRepository repo;
    private final PasswordEncoder encoder;

    public DataLoader(UserRepository repo, PasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
    }

    @Override
    public void run(String... args) {
        if (repo.findByUsername("viewer").isEmpty()) {
            repo.save(new User("viewer", encoder.encode("viewer123"), Role.VIEWER));
            repo.save(new User("regoff", encoder.encode("regoff123"), Role.REGULATORY_OFFICER));
            repo.save(new User("admin", encoder.encode("admin123"), Role.ADMIN));
        }
    }
}
