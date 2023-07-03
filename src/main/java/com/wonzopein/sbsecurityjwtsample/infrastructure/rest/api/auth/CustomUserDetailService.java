package com.wonzopein.sbsecurityjwtsample.infrastructure.rest.api.auth;

import com.wonzopein.sbsecurityjwtsample.infrastructure.persistance.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final AuthRepository authRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<User> optionalUser = authRepository.findById(username);
        if(optionalUser.isEmpty()){
            throw new UsernameNotFoundException("User not found.");
        }

        return new CustomUserDetail(optionalUser.get());
    }
}
