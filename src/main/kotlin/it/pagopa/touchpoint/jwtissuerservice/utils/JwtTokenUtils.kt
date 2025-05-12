package it.pagopa.touchpoint.jwtissuerservice.utils

import io.jsonwebtoken.Jwts
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.time.Duration
import java.time.Instant
import java.util.Date
import java.util.UUID
import org.springframework.stereotype.Component

@Component
class JwtTokenUtils {

    private val keyGen = KeyPairGenerator.getInstance("RSA") // RSA key generator
    private val keypair: KeyPair
    val kid = UUID.randomUUID().toString()

    init {
        keyGen.initialize(2048)
        keypair = keyGen.genKeyPair()
    }

    fun generateJwtToken(
        audience: String,
        tokenDuration: Duration,
        privateClaims: Map<String, Any>,
    ): String {
        val now = Instant.now()
        val issuedAtDate = Date.from(now)
        val expiryDate = Date.from(now.plus(tokenDuration))
        val headerParams = mapOf("kid" to kid)
        val issuer = "pagopa-jwt-issuer-service" // TODO differenciate wallet from ecommerce
        val jwtBuilder =
            Jwts.builder()
                .setHeaderParams(headerParams)
                .setClaims(privateClaims)
                .setId(UUID.randomUUID().toString()) // jti
                .setIssuedAt(issuedAtDate) // iat
                .setExpiration(expiryDate) // exp
                .setAudience(audience) // aud
                .setIssuer(issuer) // iss
                .signWith(keypair.private)
        return jwtBuilder.compact()
    }

    fun getKeys() = listOf(keypair.public)
}
