package com.jsf2184.sprngsecurityjwt;

import com.jsf2184.sprngsecurityjwt.models.AuthenticationRequest;
import com.jsf2184.sprngsecurityjwt.models.AuthenticationResponse;
import com.jsf2184.sprngsecurityjwt.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    public static Logger _log = LoggerFactory.getLogger(ApiController.class);


    public ApiController(AuthenticationManager authenticationManager) {
        _authenticationManager = authenticationManager;
    }

    AuthenticationManager _authenticationManager;

    @GetMapping("/")
    public String home() {
        String username = getUsername();
        String res = String.format("<h1>Welcome %s</h1>", username);
        return res;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticationRequest request) throws Exception {

        final String username = request.getUsername();
        UserDetails principal;
        try {
            UsernamePasswordAuthenticationToken loginToken;
            loginToken = new UsernamePasswordAuthenticationToken(username, request.getPassword());
            Authentication authentication = _authenticationManager.authenticate(loginToken);
            principal = (UserDetails) authentication.getPrincipal();
            _log.info("authenticate() returned principal: {}", principal);


        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect username or password");
        }
        final String jwtString = JwtUtil.generateToken(principal);
        AuthenticationResponse response = new AuthenticationResponse(jwtString);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/user")
    public String user() {
        printPrincipal();
        String username = getUsername();
        String res = String.format("<h1>Welcome User %s</h1>", username);
        return res;

    }

    @GetMapping("/admin")
    public String admin() {
        printPrincipal();
        String username = getUsername();
        String res = String.format("<h1>Welcome Admin %s</h1>", username);
        return res;
    }

    @GetMapping("/playful")
    public String playful() {
        printPrincipal();
        String username = getUsername();
        String res = String.format("<h1>Welcome Playful %s</h1>", username);
        return res;
    }

    public void printPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();
        System.out.printf("principal = %s", principal);

    }

    public String getUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = (String) authentication.getPrincipal();
        return username;
    }

}
