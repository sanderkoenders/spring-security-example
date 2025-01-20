package com.example.security.controller

import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class HelloController {
    @GetMapping("/hello")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    fun hello(): String {
        return "Hello, world!"
    }
}