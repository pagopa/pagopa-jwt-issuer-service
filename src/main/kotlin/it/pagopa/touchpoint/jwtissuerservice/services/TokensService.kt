package it.pagopa.touchpoint.jwtissuerservice.services

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenRequestDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CreateTokenResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKResponseDto
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.JWKSResponseDto
import it.pagopa.touchpoint.jwtissuerservice.utils.JwtTokenUtils
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import org.springframework.stereotype.Service

@Service
class TokensService(private val jwtTokenUtils: JwtTokenUtils) {

    suspend fun generateToken(createTokenRequest: CreateTokenRequestDto): CreateTokenResponseDto =
        CreateTokenResponseDto(
            jwtTokenUtils.generateJwtToken(
                audience = createTokenRequest.audience,
                tokenDuration = Duration.ofSeconds(createTokenRequest.duration.toLong()),
                privateClaims = createTokenRequest.privateClaims,
            )
        )

    suspend fun getJwksKeys(): JWKSResponseDto =
        JWKSResponseDto(
            propertyKeys =
                jwtTokenUtils
                    .getKeys()
                    .map { it as RSAPublicKey }
                    .map {
                        JWKResponseDto(
                            alg = it.format,
                            kty = JWKResponseDto.Kty.RSA,
                            use = "sig",
                            n = it.modulus.toString(),
                            e = it.publicExponent.toString(),
                            kid = jwtTokenUtils.kid,
                        )
                    }
        )
}
