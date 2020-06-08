package com.jsf2184.sprngsecurityjwt.filters;

import com.jsf2184.sprngsecurityjwt.util.JwtUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");
        String jwt = null;

        final String bearerHeader = "Bearer ";
        if (authorizationHeader != null && authorizationHeader.startsWith(bearerHeader)) {
            jwt = authorizationHeader.substring(bearerHeader.length());
            final UsernamePasswordAuthenticationToken authenticationToken = JwtUtil.extractAuthenticationToken(jwt);
            final SecurityContext securityContext = SecurityContextHolder.getContext();
            if (authenticationToken != null && securityContext.getAuthentication() == null) {
                securityContext.setAuthentication(authenticationToken);
            }
        }
        chain.doFilter(request, response);
    }

}
