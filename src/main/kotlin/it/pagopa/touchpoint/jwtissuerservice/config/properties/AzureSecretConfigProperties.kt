package it.pagopa.touchpoint.jwtissuerservice.config.properties

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("secret.key")
data class AzureSecretConfigProperties(val name: String, val password: String)
