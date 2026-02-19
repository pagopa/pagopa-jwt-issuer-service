package it.pagopa.touchpoint.jwtissuerservice.services

import it.pagopa.touchpoint.jwtissuerservice.models.PrivateKeyWithKid
import it.pagopa.touchpoint.jwtissuerservice.models.PublicKeyWithKid
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import reactor.test.StepVerifier

class InMemorySecurityKeysServiceTest {

    private val service = InMemorySecurityKeysService()

    @Test
    fun `Should return a private key with kid`() = runTest {
        StepVerifier.create(service.getPrivate())
            .assertNext { privateKeyWithKid ->
                assertThat(privateKeyWithKid).isInstanceOf(PrivateKeyWithKid::class.java)
                assertThat(privateKeyWithKid.kid).isNotBlank()
                assertThat(privateKeyWithKid.privateKey).isInstanceOf(ECPrivateKey::class.java)
            }
            .verifyComplete()
    }

    @Test
    fun `Should return a public key with kid`() = runTest {
        StepVerifier.create(service.getPublic())
            .assertNext { publicKeyWithKid ->
                assertThat(publicKeyWithKid).isInstanceOf(PublicKeyWithKid::class.java)
                assertThat(publicKeyWithKid.kid).isNotBlank()
                assertThat(publicKeyWithKid.publicKey).isInstanceOf(ECPublicKey::class.java)
            }
            .verifyComplete()
    }

    @Test
    fun `Should return consistent kid between private and public keys`() = runTest {
        val privateKey = service.getPrivate().block()!!
        val publicKey = service.getPublic().blockFirst()!!

        assertThat(privateKey.kid).isEqualTo(publicKey.kid)
    }

    @Test
    fun `Should return the same keys on multiple invocations`() = runTest {
        val firstPrivate = service.getPrivate().block()!!
        val secondPrivate = service.getPrivate().block()!!
        val firstPublic = service.getPublic().blockFirst()!!
        val secondPublic = service.getPublic().blockFirst()!!

        assertThat(firstPrivate.kid).isEqualTo(secondPrivate.kid)
        assertThat(firstPrivate.privateKey.encoded).isEqualTo(secondPrivate.privateKey.encoded)
        assertThat(firstPublic.kid).isEqualTo(secondPublic.kid)
        assertThat(firstPublic.publicKey.encoded).isEqualTo(secondPublic.publicKey.encoded)
    }

    @Test
    fun `Should return exactly one public key`() = runTest {
        StepVerifier.create(service.getPublic()).expectNextCount(1).verifyComplete()
    }
}
