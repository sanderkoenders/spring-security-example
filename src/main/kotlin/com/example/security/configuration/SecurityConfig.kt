package com.example.security.configuration

import com.nimbusds.jwt.JWTParser
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfig {
    @Bean
    fun securityFilterChainJwt(http: HttpSecurity): SecurityFilterChain {
        http.oauth2ResourceServer { it.jwt { jwt -> jwt.decoder(createJwtDecoder()) } }
        http.authorizeHttpRequests { authorize -> authorize.anyRequest().authenticated() }
        http.csrf { it.disable() }

        return http.build()
    }

    @Bean
    fun jwtAuthenticationConverter(): JwtAuthenticationConverter = JwtAuthenticationConverter().apply {
        setJwtGrantedAuthoritiesConverter { jwt ->
            val roles = jwt.claims["roles"]?.let { it as List<*> } ?: emptyList<String>()

            roles.map { SimpleGrantedAuthority(it.toString()) }
        }
    }

    // Please do not use this in production. It does not validate the JWT!
    private fun createJwtDecoder(): JwtDecoder = JwtDecoder { jwt ->
        val token = JWTParser.parse(jwt)

        Jwt.withTokenValue(jwt)
            .headers { headers -> headers.putAll(token.header.toJSONObject()) }
            .claims { claims -> claims.putAll(token.jwtClaimsSet.claims) }
            .issuedAt(token.jwtClaimsSet.issueTime.toInstant())
            .expiresAt(token.jwtClaimsSet.expirationTime.toInstant())
            .build()
    }
}