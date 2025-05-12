package it.pagopa.touchpoint.jwtissuerservice.controllers

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.api.TokensApi
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenRequestDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKSResponseDto
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.RestController

@RestController
class TokensController() : TokensApi {
    override suspend fun createJwtToken(
        createTokenRequestDto: CreateTokenRequestDto
    ): ResponseEntity<CreateTokenResponseDto> {
        TODO("Not yet implemented")
    }

    override suspend fun getTokenPublicKeys(): ResponseEntity<JWKSResponseDto> {
        TODO("Not yet implemented")
    }
}
