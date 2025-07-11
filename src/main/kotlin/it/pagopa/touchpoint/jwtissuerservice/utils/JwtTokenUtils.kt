package it.pagopa.touchpoint.jwtissuerservice.utils

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import it.pagopa.touchpoint.jwtissuerservice.models.PrivateKeyWithKid
import java.time.Duration
import java.time.Instant
import java.util.Date
import org.springframework.stereotype.Component

@Component
class JwtTokenUtils() {

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
        privateKey: PrivateKeyWithKid,
        jwtIssuer: String,
    ): String {
        val now = Instant.now()
        val issuedAtDate = Date.from(now)
        val expiryDate = Date.from(now.plus(tokenDuration))
        val headerParams = mapOf("kid" to privateKey.kid)
        val filteredPrivateClaims = privateClaims.filterNot { publicClaims.contains(it.key) }
        val jwtBuilder =
            Jwts.builder()
                .setHeaderParams(headerParams)
                .setClaims(filteredPrivateClaims)
                .setIssuedAt(issuedAtDate) // iat
                .setExpiration(expiryDate) // exp
                .setAudience(audience) // aud
                .setIssuer(jwtIssuer) // iss
                .signWith(privateKey.privateKey)
        return jwtBuilder.compact()
    }
}
