package it.pagopa.touchpoint.jwtissuerservice.controllers

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.api.WellKnownApi
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.OpenIDDiscoveryResponseDto
import org.springframework.http.ResponseEntity

class WellKnownController() : WellKnownApi {
    override suspend fun getOpenidInfo(): ResponseEntity<OpenIDDiscoveryResponseDto> {
        TODO("Not yet implemented")
    }
}
