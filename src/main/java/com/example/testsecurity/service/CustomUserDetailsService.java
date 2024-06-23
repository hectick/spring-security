package com.example.testsecurity.service;

import com.example.testsecurity.dto.CustomUserDetails;
import com.example.testsecurity.entity.UserEntity;
import com.example.testsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        final UserEntity userEntity = userRepository.findByUsername(username);
        if(userEntity != null) {
            return new CustomUserDetails(userEntity);
        }
        return null;
    }
}
