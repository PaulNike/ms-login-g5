package com.codigo.mslogin.service;

import com.codigo.mslogin.aggregates.request.SignInRequest;
import com.codigo.mslogin.aggregates.request.SignUpRequest;
import com.codigo.mslogin.aggregates.response.AuthenticationResponse;
import com.codigo.mslogin.entities.Usuario;

import java.util.List;

public interface AuthenticationService {
    Usuario signUpUser(SignUpRequest signUpRequest);
    Usuario signUpAdmin(SignUpRequest signUpRequest);
    List<Usuario> todos();
    AuthenticationResponse signin(SignInRequest signInRequest);
    boolean validateToken(String token);

}
