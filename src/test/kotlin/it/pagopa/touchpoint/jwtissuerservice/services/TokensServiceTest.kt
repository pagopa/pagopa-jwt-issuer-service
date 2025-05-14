package it.pagopa.touchpoint.jwtissuerservice.services

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenRequestDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKSResponseDto
import it.pagopa.touchpoint.jwtissuerservice.utils.JwtTokenUtils
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.given
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import java.util.Base64

class TokensServiceTest {

    private val jwtTokenUtils: JwtTokenUtils = mock()

    private val tokensService = TokensService(jwtTokenUtils = jwtTokenUtils)

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
        given(
                jwtTokenUtils.generateJwtToken(
                    audience = any(),
                    tokenDuration = any(),
                    privateClaims = any(),
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
            )
    }

    @Test
    fun `Should retrieve Json Web Keys successfully`() = runTest {
        // pre-conditions
        val keyGen = KeyPairGenerator.getInstance("RSA")
        val publicKey = keyGen.genKeyPair().public as RSAPublicKey
        val kid = "keyId"
        val expectedJwksResponse =
            JWKSResponseDto(
                propertyKeys =
                    listOf(
                        JWKResponseDto(
                            alg = publicKey.format,
                            kty = JWKResponseDto.Kty.RSA,
                            use = "sig",
                            n = Base64.getUrlEncoder().encodeToString(publicKey.modulus.toByteArray()),
                            e = Base64.getUrlEncoder().encodeToString(publicKey.publicExponent.toByteArray()),
                            kid = kid,
                        )
                    )
            )

        given(jwtTokenUtils.getKeys()).willReturn(listOf(publicKey))
        given(jwtTokenUtils.kid).willReturn(kid)
        // test
        val jwks = tokensService.getJwksKeys()
        assertEquals(expectedJwksResponse, jwks)
        verify(jwtTokenUtils, times(1)).getKeys()
    }
}
