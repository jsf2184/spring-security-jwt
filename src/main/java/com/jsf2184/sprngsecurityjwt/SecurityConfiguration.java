package com.jsf2184.sprngsecurityjwt;

import com.jsf2184.sprngsecurityjwt.filters.JwtRequestFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;
import java.util.List;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    JwtRequestFilter _jwtRequestFilter;

    public SecurityConfiguration(JwtRequestFilter jwtRequestFilter) {
        _jwtRequestFilter = jwtRequestFilter;
    }

    // Hard-coded implementation  of a UserDetailsService and its encapsulated role to retrieve a User
    public static final UserDetailsService FAKE_USER_DETAILS_SERVICE = s -> {
        List<SimpleGrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"), (new SimpleGrantedAuthority("ROLE_USER")));
        return new User(s, "pass", authorities);
    };

    //    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Set your configuration on the auth object
        auth.userDetailsService(FAKE_USER_DETAILS_SERVICE);
    }

    @SuppressWarnings("deprecation")
    @Bean
    public PasswordEncoder getPasswordEncoder() {
        // no password encding -- clear text. Don't do this in a real application.
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf()
            .disable()  // disable cross-site-request forgery
            // anybody can hit login endpoint
            .authorizeRequests().antMatchers("/login").permitAll()
            // any other request needs to be authenticated
            .anyRequest().authenticated()
            .and()
            // no default session management
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .addFilterBefore(_jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        // but all other requests must be authenticated first.
    }
}
