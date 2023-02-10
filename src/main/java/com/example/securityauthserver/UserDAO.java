package com.example.securityauthserver;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor

public class UserDAO {
    private long id;
    private String username;
    private String password;
    private String role;
}
