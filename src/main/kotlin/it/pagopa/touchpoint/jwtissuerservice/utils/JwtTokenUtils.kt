package it.pagopa.touchpoint.jwtissuerservice.utils

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.time.Duration
import java.time.Instant
import java.util.Date
import java.util.UUID
import org.springframework.stereotype.Component
import java.security.PrivateKey

@Component
class JwtTokenUtils {
    val kid = UUID.randomUUID().toString()
    private val publicClaims =
        setOf(
            Claims.ISSUER,
            Claims.ID,
            Claims.AUDIENCE,
            Claims.SUBJECT,
            Claims.EXPIRATION,
            Claims.ISSUED_AT,
            Claims.NOT_BEFORE,
        )

    fun generateJwtToken(
        audience: String,
        tokenDuration: Duration,
        privateClaims: Map<String, Any>,
        privateKey: PrivateKey
    ): String {
        val now = Instant.now()
        val issuedAtDate = Date.from(now)
        val expiryDate = Date.from(now.plus(tokenDuration))
        val headerParams = mapOf("kid" to kid)
        val issuer = "pagopa-jwt-issuer-service" // TODO differenciate wallet from ecommerce
        val filteredPrivateClaims = privateClaims.filterNot { publicClaims.contains(it.key) }
        val jwtBuilder =
            Jwts.builder()
                .setHeaderParams(headerParams)
                .setClaims(filteredPrivateClaims)
                .setId(UUID.randomUUID().toString()) // jti
                .setIssuedAt(issuedAtDate) // iat
                .setExpiration(expiryDate) // exp
                .setAudience(audience) // aud
                .setIssuer(issuer) // iss
                .signWith(privateKey)
        return jwtBuilder.compact()
    }
}
