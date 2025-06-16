package it.pagopa.touchpoint.jwtissuerservice.controllers

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.api.WellKnownApi
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.OpenIDDiscoveryResponseDto
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.RestController

@RestController
class WellKnownController(
    @Value("\${jwt.issuer}") private val jwtIssuer: String,
    @Value("\${well-known.openid-configuration.base-path}")
    private val wellKnownOpenidConfigurationBasePath: String,
) : WellKnownApi {
    private val logger = LoggerFactory.getLogger(javaClass)

    override suspend fun getOpenidInfo(): ResponseEntity<OpenIDDiscoveryResponseDto> {
        logger.info("Getting OpenID Info")
        return ResponseEntity.ok(
            OpenIDDiscoveryResponseDto(
                jwksUri = "$wellKnownOpenidConfigurationBasePath/tokens/keys",
                subjectTypesSupported = listOf("public"),
                tokenEndpoint = "$wellKnownOpenidConfigurationBasePath/tokens",
                idTokenSigningAlgValuesSupported = listOf("RS256", "ES256"),
                responseTypesSupported = listOf("code"),
                authorizationEndpoint = "https://not-supported",
                issuer = jwtIssuer,
            )
        )
    }
}
