package com.codigo.mslogin.controller;

import com.codigo.mslogin.aggregates.request.SignInRequest;
import com.codigo.mslogin.aggregates.request.SignUpRequest;
import com.codigo.mslogin.aggregates.response.AuthenticationResponse;
import com.codigo.mslogin.entities.Usuario;
import com.codigo.mslogin.service.AuthenticationService;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Key;
import java.util.Base64;
import java.util.List;

@RestController
@RequestMapping("/api/v1/autenticacion")
@RequiredArgsConstructor
public class AutenticacionController {
    private final AuthenticationService authenticationService;

    @PostMapping("/signupuser")
    public ResponseEntity<Usuario> signUpUser(@RequestBody SignUpRequest signUpRequest){
        return ResponseEntity.ok(authenticationService.signUpUser(signUpRequest));
    }
    @PostMapping("/signupadmin")
    public ResponseEntity<Usuario> signUpAdmin(@RequestBody SignUpRequest signUpRequest){
        return ResponseEntity.ok(authenticationService.signUpAdmin(signUpRequest));
    }


    @PostMapping("/signin")
    public ResponseEntity<AuthenticationResponse> signin(@RequestBody SignInRequest signInRequest){
        return ResponseEntity.ok(authenticationService.signin(signInRequest));
    }
    @PostMapping("/validateToken")
    public ResponseEntity<Boolean> validateToken(@RequestHeader("validate") String validate){
        return ResponseEntity.ok(authenticationService.validateToken(validate));
    }
    @GetMapping("/todos")
    public ResponseEntity<List<Usuario>> todos(){
        return ResponseEntity.ok(authenticationService.todos());
    }
    @GetMapping("/claveToken")
    public ResponseEntity<String> clavetoken(){
        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String dato = Base64.getEncoder().encodeToString(key.getEncoded());
        return ResponseEntity.ok(dato);
    }
}
