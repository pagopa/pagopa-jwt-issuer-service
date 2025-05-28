package it.pagopa.touchpoint.jwtissuerservice.controllers

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.api.WellKnownApi
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.OpenIDDiscoveryResponseDto
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.RestController

@RestController
class WellKnownController() : WellKnownApi {
    override suspend fun getOpenidInfo(): ResponseEntity<OpenIDDiscoveryResponseDto> {
        return ResponseEntity.ok(
            OpenIDDiscoveryResponseDto(
                jwksUri =
                    "https://weudev.ecommerce.internal.dev.platform.pagopa.it/pagopa-jwt-issuer-service/tokens/keys",
                subjectTypesSupported = listOf("public"),
                tokenEndpoint =
                    "https://weudev.ecommerce.internal.dev.platform.pagopa.it/pagopa-jwt-issuer-service/tokens",
                idTokenSigningAlgValuesSupported = listOf("RS256"),
                responseTypesSupported = listOf("code"),
                authorizationEndpoint = "https://not-supported",
                issuer = "pagopa-ecommerce-jwt-issuer-service",
            )
        )
    }
}
