package it.pagopa.touchpoint.jwtissuerservice.controllers

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.api.TokensApi
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenRequestDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKSResponseDto
import it.pagopa.touchpoint.jwtissuerservice.mdcutilities.LogTracingUtils
import it.pagopa.touchpoint.jwtissuerservice.mdcutilities.LogTracingUtils.AttributeKeys
import it.pagopa.touchpoint.jwtissuerservice.services.TokensService
import kotlinx.coroutines.reactive.awaitSingle
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.RestController

@RestController
class TokensController(private val tokensService: TokensService) : TokensApi {
    override suspend fun createJwtToken(
        createTokenRequestDto: CreateTokenRequestDto
    ): ResponseEntity<CreateTokenResponseDto> =
        tokensService
            .generateToken(createTokenRequestDto)
            .contextWrite { context ->
                LogTracingUtils.enrichContextForEvent(
                    mapOf(
                        AttributeKeys.CTX_TRANSACTION_ID to
                            createTokenRequestDto.privateClaims["transactionId"],
                        AttributeKeys.CTX_AUTHORIZATION_REQUEST_ID to
                            createTokenRequestDto.privateClaims["orderId"],
                        AttributeKeys.CTX_WALLET_ID to
                            createTokenRequestDto.privateClaims["walletId"],
                    ),
                    context,
                )
            }
            .map { v -> ResponseEntity.ok(v) }
            .awaitSingle()

    override suspend fun getTokenPublicKeys(): ResponseEntity<JWKSResponseDto> =
        tokensService.getJwksKeys().map { v -> ResponseEntity.ok(v) }.awaitSingle()
}
