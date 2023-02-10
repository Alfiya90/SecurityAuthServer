package com.example.securityauthserver;

import org.springframework.security.core.userdetails.User;

public interface UserRepository {
    User findByUsername(String username);

}
