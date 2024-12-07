package com.crm.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers("/login", "/css/**", "/js/**").permitAll() // Allow login page and static resources
                                .anyRequest().authenticated() // All other requests require authentication
                )
                .formLogin(form -> form
                        .loginPage("/login") // Custom login page URL
                        .defaultSuccessUrl("/home", true) // Redirect after successful login
                        .permitAll() // Allow everyone to access the login page
                )
                .logout(logout -> logout
                        .logoutUrl("/logout") // URL for logging out
                        .logoutSuccessUrl("/login?logout") // Redirect after logout
                        .invalidateHttpSession(true) // Invalidate session
                        .deleteCookies("JSESSIONID") // Clear cookies
                        .permitAll() // All users to access logout
                );
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
