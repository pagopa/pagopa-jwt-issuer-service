package it.pagopa.touchpoint.jwtissuerservice.services

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenRequestDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKSResponseDto
import it.pagopa.touchpoint.jwtissuerservice.models.PrivateKeyWithKid
import it.pagopa.touchpoint.jwtissuerservice.models.PublicKeyWithKid
import it.pagopa.touchpoint.jwtissuerservice.utils.JwtTokenUtils
import it.pagopa.touchpoint.jwtissuerservice.utils.KeyGenerationTestUtils.Companion.getKeyPair
import java.math.BigInteger
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.util.Base64
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.given
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

class TokensServiceTest {

    private val jwtTokenUtils: JwtTokenUtils = mock()
    private val kvService: ReactiveAzureKVSecurityKeysService = mock()

    private val tokensService =
        TokensService(
            jwtTokenUtils = jwtTokenUtils,
            reactiveAzureKVSecurityKeysService = kvService,
            jwtIssuer = "jwtIssuer",
        )

    @Test
    fun `Should generate token successfully`() = runTest {
        // pre-conditions
        val audience = "aud"
        val duration = Duration.ofSeconds(1)
        val privateClaims = mapOf("key" to "value")
        val createTokenRequestDto =
            CreateTokenRequestDto(
                audience = audience,
                duration = duration.seconds.toInt(),
                privateClaims = privateClaims,
            )
        val token = "jwtToken"
        val privateKey = getKeyPair()
        val privateKeyWithKid = PrivateKeyWithKid("kid", privateKey.private)
        given(kvService.getPrivate()).willReturn(Mono.just(privateKeyWithKid))
        given(
                jwtTokenUtils.generateJwtToken(
                    audience = any(),
                    tokenDuration = any(),
                    privateClaims = any(),
                    privateKey = any(),
                    jwtIssuer = any(),
                )
            )
            .willReturn(token)
        // test
        val generateTokenResponse = tokensService.generateToken(createTokenRequestDto)
        assertEquals(token, generateTokenResponse.token)
        verify(jwtTokenUtils, times(1))
            .generateJwtToken(
                audience = audience,
                tokenDuration = duration,
                privateClaims = privateClaims,
                privateKey = privateKeyWithKid,
                jwtIssuer = "jwtIssuer",
            )
    }

    @Test
    fun `Should retrieve Json Web Keys successfully`() = runTest {
        // pre-conditions
        val keyPair = getKeyPair()
        val kid = "keyId"
        val publicKey: RSAPublicKey = keyPair.public as RSAPublicKey
        val publicKeyWithKid = PublicKeyWithKid(kid, keyPair.public)
        val expectedJwksResponse =
            JWKSResponseDto(
                propertyKeys =
                    listOf(
                        JWKResponseDto(
                            alg = publicKey.format,
                            kty = JWKResponseDto.Kty.RSA,
                            use = "sig",
                            n = base64UrlEncodeUnsigned(publicKey.modulus),
                            e = base64UrlEncodeUnsigned(publicKey.publicExponent),
                            kid = kid,
                        )
                    )
            )
        given(kvService.getPublic()).willReturn(Flux.just(publicKeyWithKid))
        // test
        val jwks = tokensService.getJwksKeys()
        assertEquals(expectedJwksResponse, jwks)
        verify(kvService, times(1)).getPublic()
    }

    private fun base64UrlEncodeUnsigned(value: BigInteger): String {
        var bytes = value.toByteArray()

        // Remove leading 0x00 if present
        if (bytes.size > 1 && bytes[0] == 0.toByte()) {
            bytes = bytes.copyOfRange(1, bytes.size)
        }

        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}
