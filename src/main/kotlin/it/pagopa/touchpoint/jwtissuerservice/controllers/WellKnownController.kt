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
                jwksUri = "http://localhost/tokens/keys",
                subjectTypesSupported = listOf("subject_types_supported"),
                tokenEndpoint = "token_endpoint",
                idTokenSigningAlgValuesSupported = listOf("idTokenSigningAlgValuesSupported"),
                responseTypesSupported = listOf("responseTypesSupported"),
                authorizationEndpoint = "http://not-supported",
                issuer = "issuer",
            )
        )
    }
}
