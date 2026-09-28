package it.pagopa.touchpoint.jwtissuerservice.controllers

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.api.TokensApi
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CertificatesResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenRequestDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKSResponseDto
import it.pagopa.touchpoint.jwtissuerservice.exceptions.RestApiException
import it.pagopa.touchpoint.jwtissuerservice.mdcutilities.LogTracingUtils
import it.pagopa.touchpoint.jwtissuerservice.mdcutilities.LogTracingUtils.AttributeKeys
import it.pagopa.touchpoint.jwtissuerservice.services.CertificatesService
import it.pagopa.touchpoint.jwtissuerservice.services.TokensService
import kotlinx.coroutines.reactive.awaitSingle
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Mono

@RestController
class TokensController(
    private val tokensService: TokensService,
    private val certificatesService: CertificatesService,
) : TokensApi {
    override suspend fun createJwtToken(
        createTokenRequestDto: CreateTokenRequestDto
    ): ResponseEntity<CreateTokenResponseDto> =
        tokensService
            .generateToken(createTokenRequestDto)
            .contextWrite { context ->
                LogTracingUtils.enrichContextForEvent(
                    buildMap {
                        createTokenRequestDto.privateClaims["transactionId"]?.let {
                            put(AttributeKeys.CTX_TRANSACTION_ID, it)
                        }
                        createTokenRequestDto.privateClaims["orderId"]?.let {
                            put(AttributeKeys.CTX_AUTHORIZATION_REQUEST_ID, it)
                        }
                        createTokenRequestDto.privateClaims["walletId"]?.let {
                            put(AttributeKeys.CTX_WALLET_ID, it)
                        }
                    },
                    context,
                )
            }
            .map { v -> ResponseEntity.ok(v) }
            .awaitSingle()

    override suspend fun getTokenPublicCertificates(
        certificateName: String,
        validForDays: Int,
    ): ResponseEntity<CertificatesResponseDto> {
        return certificatesService
            .getCertificateByNameAndValidity(certificateName, validForDays)
            .switchIfEmpty(
                Mono.error(
                    RestApiException(
                        HttpStatus.NOT_FOUND,
                        "Unable to retrieve certificates",
                        "No valid KeyVault certificate found ",
                    )
                )
            )
            .map { v -> ResponseEntity.ok(v) }
            .awaitSingle()
    }

    override suspend fun getTokenPublicKeys(): ResponseEntity<JWKSResponseDto> =
        tokensService.getJwksKeys().map { v -> ResponseEntity.ok(v) }.awaitSingle()
}
