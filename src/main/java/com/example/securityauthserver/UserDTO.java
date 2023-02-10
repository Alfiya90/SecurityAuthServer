package com.example.securityauthserver;

import lombok.Data;

@Data
public class UserDTO {
    private String username;
    private String password;
    private  String role;
}
