package com.security.securitySpring.auth;

import com.security.securitySpring.Entity.Roles;
import com.security.securitySpring.Entity.User;
import com.security.securitySpring.repository.UserRepository;

import com.security.securitySpring.security.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
public class AuthenticationService {

    @Autowired
    private  UserRepository userRepository ;

    private final PasswordEncoder passwordEncoder   ;

    @Autowired
    private JwtService jwtService ;
    @Autowired
    private AuthenticationManager authenticationManager;


    public AuthenticationService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    public AuthenticationResponse register(RegisterRequest request) {
        System.out.print(request.getPassword());
        System.out.print(request.getFirstname());
        System.out.print(request.getLastname());

        var user =  User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Roles.USER)
                .build() ;

        System.out.print(user);
        userRepository.save(user);
        var jwtToken = jwtService.generateTokenJwt(user);

        return  AuthenticationResponse.builder()
                .token(jwtToken)
                .build() ;
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            request.getPassword()
            )
        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateTokenJwt(user) ;

        System.out.print(jwtToken);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build() ;
    }
}
