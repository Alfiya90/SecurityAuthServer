package com.example.securityauthserver.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@EnableWebSecurity
@Configuration
public class SecurityConfig  {



    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
      public  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        return http.authorizeRequests(authorizeRequests ->
                authorizeRequests.anyRequest().authenticated())
                .formLogin()
                .and()
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        List<UserDetails> usersList = new ArrayList<>();
        usersList.add(new User(
                "buzz",encoder.encode("password"),
                Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"))));
        usersList.add(new User(
                "woody", encoder.encode("password"),
                Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"))));
        return new InMemoryUserDetailsManager(usersList);
    }

   /* @Bean
    UserDetailsService userDetailsService(UserRepository userRepository) {
        return username -> (UserDetails) userRepository.findByUsername(username);
    }*/



   /* @Bean
    public ApplicationRunner dataLoader(
            UserRepository repo, PasswordEncoder encoder) {
        return args -> {

            repo.save(
                    new User("habuma", encoder.encode("password"), "ROLE_ADMIN"));
            repo.save(
                    new User("tacochef", encoder.encode("password"), "ROLE_ADMIN"));
        };
    }*/
}

