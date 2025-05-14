package it.pagopa.touchpoint.jwtissuerservice

import it.pagopa.touchpoint.jwtissuerservice.config.properties.AzureSecretConfigProperties
import it.pagopa.touchpoint.jwtissuerservice.config.properties.CacheConfigProperties
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication
import reactor.core.publisher.Hooks

@SpringBootApplication
@EnableConfigurationProperties(AzureSecretConfigProperties::class, CacheConfigProperties::class)
class JwtIssuerServiceApplication

fun main(args: Array<String>) {
    Hooks.enableAutomaticContextPropagation()
    runApplication<JwtIssuerServiceApplication>(*args)
}
