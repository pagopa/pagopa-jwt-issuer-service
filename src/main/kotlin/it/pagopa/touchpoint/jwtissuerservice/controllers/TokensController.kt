package it.pagopa.touchpoint.jwtissuerservice.controllers

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.api.TokensApi
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenRequestDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKSResponseDto
import it.pagopa.touchpoint.jwtissuerservice.services.TokensService
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.RestController

@RestController
class TokensController(private val tokensService: TokensService) : TokensApi {
    override suspend fun createJwtToken(
        createTokenRequestDto: CreateTokenRequestDto
    ): ResponseEntity<CreateTokenResponseDto> =
        ResponseEntity.ok(tokensService.generateToken(createTokenRequestDto))

    override suspend fun getTokenPublicKeys(): ResponseEntity<JWKSResponseDto> =
        ResponseEntity.ok(tokensService.getJwksKeys())
}
