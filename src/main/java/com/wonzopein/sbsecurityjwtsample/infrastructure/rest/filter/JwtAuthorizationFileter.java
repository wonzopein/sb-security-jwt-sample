package com.wonzopein.sbsecurityjwtsample.infrastructure.rest.filter;

import com.wonzopein.sbsecurityjwtsample.infrastructure.rest.common.JwtTokenUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthorizationFileter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader(JwtTokenUtil.AUTH_HEADER);
        String token = null;

        try {
            if (authorizationHeader != null && authorizationHeader.startsWith(JwtTokenUtil.TOKEN_TYPE + " ")) {
                token = authorizationHeader.substring(7);
            }

            if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                //log.info("username: {}", jwtTokenUtil.extractUsername(token));

                if(!jwtTokenUtil.validateToken(token)){
                    log.info("token is invalid");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                    return;
                }

                //  토큰 유효성 검증 후 SecurityContextHolder 주입하기

                SecurityContextHolder.getContext().setAuthentication(jwtTokenUtil.getAuthentication(token));
            }
        } catch (Exception e){
            log.error("token is invalid", e);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
            return;
        }



        filterChain.doFilter(request, response);
    }

}
