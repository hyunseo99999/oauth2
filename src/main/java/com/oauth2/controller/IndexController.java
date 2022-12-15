package com.oauth2.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "Index";
    }

    @GetMapping("/api/user")
    public Authentication user(Authentication authentication) {
        return authentication;
    }

}
