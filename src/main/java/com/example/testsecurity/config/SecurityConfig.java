package com.example.testsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티로 관리
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 경로에 대한 접근 권한 설정. 동작 순서는 상단부터 동작되기 때문에 순서에 유의하여 적어야 함.
        // ex) 상단에서 모든 경로에 대해 permitAll하면 밑에서 접근제한건게 동작하지 않음.
        // 시큐리티는 버전별로 구현 방식이 달라짐 -> 스프링부트 3.1.x 버전부터는 내부에 필수적으로 람다형식으로 지정해야만 동작한다.
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/").hasAnyRole("A") //  A < B < C 일 때 A, B, C
                        .requestMatchers("/manager").hasAnyRole("B") // B, C
                        .requestMatchers("/admin").hasAnyRole("C") // C
                        .anyRequest().authenticated()
                );

        http
                .httpBasic(Customizer.withDefaults());

/*                .formLogin((auth) -> auth.loginPage("/login") // 로그인 페이지 경로 설정
                        .loginProcessingUrl("/loginProc") // 로그인 경로를 특정 경로("/loginProc")로 보냄
                        .permitAll() // 아무나 들어올 수 있음
                );*/

        // 기본적으로 csrf 설정이 자동으로 설정되어있는데, post 요청을 보낼때 csrf 토큰도 보내야 함. 그래서 개발환경에서는 disable 시킨다.
/*        http
                .csrf((auth) -> auth.disable());*/

        http
                .sessionManagement((auth) -> auth
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(true)); //위의 다중로그인 값을 초과했을 경우 기존에 로그인되어있는 놈을 로그아웃시킬지, 새로 로그인하는 넘을 막을지. true -> 새로운 로그인 차단, false -> 기존 로그인 하나 삭제

        // 세션 고정 보호
        http
                .sessionManagement((auth) -> auth
                        .sessionFixation().changeSessionId());
        return http.build();
    }

    //내부에 유저를 등록해두고 인메모리로 관리
    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails user1 = User.builder()
                .username("user1")
                .password(bCryptPasswordEncoder().encode("1234"))
                .roles("A")
                .build();

        UserDetails user2 = User.builder()
                .username("user2")
                .password(bCryptPasswordEncoder().encode("1234"))
                .roles("C")
                .build();

        return new InMemoryUserDetailsManager(user1, user2);
    }

    //계층 권한 메소드 등
    @Bean
    public RoleHierarchy roleHierarchy() {

        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();

        hierarchy.setHierarchy("ROLE_C > ROLE_B\n" +
                "ROLE_B > ROLE_A");

        return hierarchy;
    }
}
