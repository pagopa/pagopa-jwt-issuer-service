package it.pagopa.touchpoint.jwtissuerservice.utils

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import it.pagopa.touchpoint.jwtissuerservice.models.PrivateKeyWithKid
import it.pagopa.touchpoint.jwtissuerservice.utils.KeyGenerationTestUtils.Companion.getKeyPair
import java.time.Duration
import java.time.Instant
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class JwtTokenUtilsTest {

    private val jwtTokenUtils = JwtTokenUtils()

    @Test
    fun `Should generate token successfully filtering out public claims from input private ones`() {
        // pre conditions
        val audience = "audience"
        val tokenDuration = Duration.ofMinutes(1)
        val privateKey = getKeyPair()
        val privateKeyWithKid = PrivateKeyWithKid("kid", privateKey.private)
        // public reserver claims that will be filtered out by app code
        val illegalPrivateClaims =
            mapOf(
                Claims.ISSUER to "OVERRIDDEN",
                Claims.ID to "OVERRIDDEN",
                Claims.AUDIENCE to "OVERRIDDEN",
                Claims.SUBJECT to "OVERRIDDEN",
                Claims.EXPIRATION to "OVERRIDDEN",
                Claims.ISSUED_AT to "OVERRIDDEN",
                Claims.NOT_BEFORE to "OVERRIDDEN",
            )
        // application custom claims
        val legitPrivateClaims =
            mapOf("testClaimKey1" to "testClaimValue1", "testClaimKey2" to "testClaimValue2")
        val privateClaims = illegalPrivateClaims + legitPrivateClaims

        // test
        val generatedToken =
            jwtTokenUtils.generateJwtToken(
                audience = audience,
                tokenDuration = tokenDuration,
                privateClaims = privateClaims,
                privateKey = privateKeyWithKid,
                jwtIssuer = "jwtIssuer",
            )
        val parsedToken =
            Jwts.parserBuilder().setSigningKey(privateKey.public).build().parse(generatedToken)
        val header = parsedToken.header
        val body = parsedToken.body as Claims
        // verify header claims
        assertEquals(privateKeyWithKid.kid, header["kid"])
        assertEquals("ES256", header["alg"])
        // verify body claims
        val expirationClaim = body[Claims.EXPIRATION] as Int
        val issuedAtClaim = body[Claims.ISSUED_AT] as Int
        val expirationInstant = Instant.ofEpochMilli(expirationClaim * 1000L)
        val issuedAtInstant = Instant.ofEpochMilli(issuedAtClaim * 1000L)
        assertEquals(tokenDuration, Duration.between(issuedAtInstant, expirationInstant))
        assertNotNull(body[Claims.ID])
        assertEquals(audience, body[Claims.AUDIENCE])
        assertEquals("jwtIssuer", body[Claims.ISSUER])
        assertNull(body[Claims.SUBJECT])
        assertNull(body[Claims.NOT_BEFORE])
        legitPrivateClaims.forEach {
            assertEquals(
                it.value,
                body[it.key],
                "legit claim with key: [${it.key}] not found into generated token",
            )
        }
        illegalPrivateClaims.forEach {
            assertNotEquals(
                it.value,
                body[it.key],
                "public claim with key: [${it.key}] have been not filtered out",
            )
        }
    }
}
