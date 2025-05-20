package it.pagopa.touchpoint.jwtissuerservice.services

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenRequestDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKSResponseDto
import it.pagopa.touchpoint.jwtissuerservice.utils.JwtTokenUtils
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.util.*
import kotlinx.coroutines.reactive.awaitSingle
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service

@Service
class TokensService(
    private val jwtTokenUtils: JwtTokenUtils,
    private val reactiveAzureKVSecurityKeysService: IReactiveSecurityKeysService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun generateToken(createTokenRequest: CreateTokenRequestDto): CreateTokenResponseDto =
        reactiveAzureKVSecurityKeysService
            .getPrivate()
            .map {
                CreateTokenResponseDto(
                    jwtTokenUtils.generateJwtToken(
                        audience = createTokenRequest.audience,
                        tokenDuration = Duration.ofSeconds(createTokenRequest.duration.toLong()),
                        privateClaims = createTokenRequest.privateClaims,
                        privateKey = it,
                    )
                )
            }
            .doOnNext { logger.info("Token generated successfully") }
            .awaitSingle()

    suspend fun getJwksKeys(): JWKSResponseDto =
        reactiveAzureKVSecurityKeysService
            .getPublic()
            .map {
                val rsaPublicKey = it.publicKey as RSAPublicKey
                JWKResponseDto(
                    alg = rsaPublicKey.format,
                    kty = JWKResponseDto.Kty.RSA,
                    use = "sig",
                    n = Base64.getUrlEncoder().encodeToString(rsaPublicKey.modulus.toByteArray()),
                    e =
                        Base64.getUrlEncoder()
                            .encodeToString(rsaPublicKey.publicExponent.toByteArray()),
                    kid = it.kid,
                )
            }
            .collectList()
            .map { JWKSResponseDto(propertyKeys = it) }
            .doOnNext {
                logger.info("Public keys list retrieved, number of keys: ${it.propertyKeys.size}")
            }
            .awaitSingle()
}
