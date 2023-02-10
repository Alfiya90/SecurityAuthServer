package com.example.securityauthserver;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

public interface RegisteredClientRepository {
    @Nullable
    RegisteredClient findById(String id);
    @Nullable
    RegisteredClient findbyclintId(String clientId);
}
