package com.bardiniww.security.config;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_TOKEN_MANDATORY_PREFIX = "Bearer ";

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        //extract token from request
        final String authHeader = request.getHeader("Authorization");
        boolean authHeaderIsInvalid =
                StringUtils.isEmpty(authHeader) || !authHeader.startsWith(AUTH_TOKEN_MANDATORY_PREFIX);

        if (authHeaderIsInvalid) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);
        final String userName = jwtService.extractUserName(jwt); //todo impl
    }
}
