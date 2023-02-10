package com.example.securityauthserver.config;

import com.example.securityauthserver.RegisteredClientRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.SecurityFilterChain;

import java.util.UUID;

public class AuthorizationServerConfig {

    @Bean
    //т Ordered.HIGHEST_PRECEDENCE, гарантируя, что если по какой-то причине будут объявлены
    //другие bean-компоненты этого же типа, то данный компонент будет
    //иметь приоритет над другими
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults())
                .build();
    }

    @Bean
    InMemoryRegisteredClientRepository registeredClientRepository(PasswordEncoder encoder) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("taco-admin-client")
                .clientSecret(encoder.encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127/0/0/1/9090/login/oauth2/code/taco-admin-client")
                .scope("writeIngredients")
                .scope("deleteIngredients")
                .scope(OidcScopes.OPENID)
                .clientSettings(clientSettings -> clientSettings.requireUserConsent(true))
                .build();
        return  new InMemoryRegisteredClientRepository(registeredClient);
    }
}
