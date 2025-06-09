package it.pagopa.touchpoint.jwtissuerservice.services

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenRequestDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKSResponseDto
import it.pagopa.touchpoint.jwtissuerservice.utils.JwtTokenUtils
import java.math.BigInteger
import java.security.interfaces.ECPublicKey
import java.time.Duration
import java.util.*
import kotlinx.coroutines.reactive.awaitSingle
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service

@Service
class TokensService(
    private val jwtTokenUtils: JwtTokenUtils,
    private val reactiveAzureKVSecurityKeysService: IReactiveSecurityKeysService,
    @Value("\${jwt.issuer}") private val jwtIssuer: String,
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
                        jwtIssuer = jwtIssuer,
                    )
                )
            }
            .doOnNext { logger.info("Token generated successfully") }
            .awaitSingle()

    suspend fun getJwksKeys(): JWKSResponseDto =
        reactiveAzureKVSecurityKeysService
            .getPublic()
            .map {
                when (val publicKey = it.publicKey) {
                    is ECPublicKey ->
                        JWKResponseDto(
                            alg = "ES${publicKey.params.curve.field.fieldSize}",
                            kty = JWKResponseDto.Kty.EC,
                            use = "sig",
                            crv = "P-${publicKey.params.curve.field.fieldSize}",
                            x = base64UrlEncodeUnsigned(publicKey.w.affineX),
                            y = base64UrlEncodeUnsigned(publicKey.w.affineY),
                            kid = it.kid,
                        )
                    else ->
                        throw IllegalArgumentException(
                            "Unsupported key type: ${publicKey.algorithm}"
                        )
                }
            }
            .collectList()
            .map { JWKSResponseDto(propertyKeys = it) }
            .doOnNext {
                logger.info("Public keys list retrieved, number of keys: ${it.propertyKeys.size}")
            }
            .awaitSingle()

    private fun base64UrlEncodeUnsigned(value: BigInteger): String {
        var bytes = value.toByteArray()

        // Remove leading 0x00 if present
        if (bytes.size > 1 && bytes[0] == 0.toByte()) {
            bytes = bytes.copyOfRange(1, bytes.size)
        }

        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}
