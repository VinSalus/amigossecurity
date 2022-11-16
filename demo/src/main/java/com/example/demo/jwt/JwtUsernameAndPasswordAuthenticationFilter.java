package com.example.demo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

private final AuthenticationManager authenticationManager;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try{
            //Object mapper reads the inputStream and puts it into the UsernameAndPasswordAuthenticationRequest class
            UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
                    .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

            //UsernamePasswordAuthenticationToken is an implementation of interface Authentication
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(), //authentication principal
                    authenticationRequest.getPassword() // authentication credential
            );

            //AuthenticationManager will check if the username exists and if it exists it will check whether the
            //password is correct or not and if that's the case this request will be authenticated
            Authentication authenticate = authenticationManager.authenticate(authentication);
            return authenticate;

        } catch(IOException e){
            throw new RuntimeException(e);
        }

    }
    //This method gets executed if attemptAuthentication is successful. It builds the JWT Token.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpSerletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
      String key = "verysecurekeywowthisisverysecure";
        String token = Jwts.builder()
                .setSubject(authResult.getName()) //Gets the user
                .claim("authorities", authResult.getAuthorities()) //Gets the authorities
                .setIssuedAt(new Date()) //Date when the token was generated
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2))) //Token expiration time
                .signWith(Keys.hmacShaKeyFor(key.getBytes())) //Receives the key and encrypt it
                .compact(); //Builds the token

    //In response to a request send this token to the header
    //so that the user is authorized
     response.addHeader("Authorization", "Bearer" + token);
    }
}
