package com.example.testsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티로 관리
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 경로에 대한 접근 권한 설정. 동작 순서는 상단부터 동작되기 때문에 순서에 유의하여 적어야 함.
        // ex) 상단에서 모든 경로에 대해 permitAll하면 밑에서 접근제한건게 동작하지 않음.
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login").permitAll() // 모든 사용자가 로그인을 하지 않아도 접근 가능
                        .requestMatchers("/admin").hasRole("ADMIN") // ADMIN 롤이 있어야 경로에 접근 가능
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER") // 여러 롤 설정 가능
                        .anyRequest().authenticated() // 위엥서 처리못한 나머지 경로는 로그인만 진행하면 모두 접근 가능. denyAll하면 모든 사용자가 접근 불가능하도록
                );

        return http.build();
    }
}
