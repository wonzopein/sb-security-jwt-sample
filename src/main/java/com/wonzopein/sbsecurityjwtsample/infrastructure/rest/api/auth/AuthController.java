package com.wonzopein.sbsecurityjwtsample.infrastructure.rest.api.auth;

import com.wonzopein.sbsecurityjwtsample.infrastructure.consts.auth.Role;
import com.wonzopein.sbsecurityjwtsample.infrastructure.rest.common.JwtTokenUtil;
import com.wonzopein.sbsecurityjwtsample.infrastructure.rest.model.auth.AuthenticationDto;
import jakarta.annotation.PostConstruct;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final BCryptPasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;
    private final JwtTokenUtil jwtTokenUtil;
    private final AuthRepository authRepository;

    @PostConstruct
    public void init() {
        log.info("AuthController initialized");
        var user = new com.wonzopein.sbsecurityjwtsample.infrastructure.persistance.model.User();
        user.setUsername("wonzopein");
        user.setPassword(passwordEncoder.encode("wonzopein"));
        user.setRole(Role.USER);
        authRepository.save(user);
    }

    @PostMapping("/signin")
    public AuthenticationDto.SigninResponse signin(@RequestBody @Valid AuthenticationDto.SigninRequest signinRequest) {

        UserDetails userDetails = userDetailsService.loadUserByUsername(signinRequest.getUsername());

        if (passwordEncoder.matches(signinRequest.getPassword(), userDetails.getPassword())) {

            User principal = new User(userDetails.getUsername(), "", userDetails.getAuthorities());
            var authentication = new UsernamePasswordAuthenticationToken(principal, "", principal.getAuthorities());

            return new AuthenticationDto.SigninResponse(
                    jwtTokenUtil.createJwtToken(authentication)
                    ,userDetails.getUsername());
        };

        return null;
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/users")
    public Iterable<com.wonzopein.sbsecurityjwtsample.infrastructure.persistance.model.User> getUsers() {
        return authRepository.findAll();
    }

}
