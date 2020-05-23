package com.ankit.samplejwtauth.resource;

import com.ankit.samplejwtauth.resource.models.AuthenticationRequest;
import com.ankit.samplejwtauth.resource.models.AuthenticationResponse;
import com.ankit.samplejwtauth.util.Jwtutil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloResource {

    @Autowired
    private Jwtutil jwtutil;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @RequestMapping(value = "/hello", method = RequestMethod.GET)
    public String hello(){
        return "<h1>Hello World!</h1>";
    }

    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthernticationRequest(@RequestBody AuthenticationRequest authenticationRequest) throws Exception{
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
            );
        }
        catch(BadCredentialsException e){
            throw new Exception("Incorrect Username and Password", e);
        }

        final UserDetails userDetails = userDetailsService
                .loadUserByUsername(authenticationRequest.getUsername());

        final String jwt = jwtutil.generateToken(userDetails);

        AuthenticationResponse authenticationResponse = new AuthenticationResponse(jwt);

        return ResponseEntity.ok(authenticationResponse);
    }
}
