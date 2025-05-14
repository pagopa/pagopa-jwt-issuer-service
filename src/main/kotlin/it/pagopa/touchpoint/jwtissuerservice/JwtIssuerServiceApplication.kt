package it.pagopa.touchpoint.jwtissuerservice

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.cache.annotation.EnableCaching
import reactor.core.publisher.Hooks

@SpringBootApplication @EnableCaching class JwtIssuerServiceApplication

fun main(args: Array<String>) {
    Hooks.enableAutomaticContextPropagation()
    runApplication<JwtIssuerServiceApplication>(*args)
}
