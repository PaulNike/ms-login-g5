package com.codigo.mslogin.controller;

import com.codigo.mslogin.aggregates.request.SignInRequest;
import com.codigo.mslogin.aggregates.request.SignUpRequest;
import com.codigo.mslogin.aggregates.response.AuthenticationResponse;
import com.codigo.mslogin.entities.Usuario;
import com.codigo.mslogin.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/autenticacion")
@RequiredArgsConstructor
@Log4j2
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
    @GetMapping("/todos")
    public ResponseEntity<List<Usuario>> getTodos(){
        log.info("INFORMACION SE DEVUELVE DESDE MS LOGIN - TODOS");
        return ResponseEntity.ok(authenticationService.todos());
    }
    @PostMapping("/validateToken")
    public ResponseEntity<Boolean> validateToken(@RequestHeader("validate") String validate){
        return ResponseEntity.ok(authenticationService.validateToken(validate));
    }
}
