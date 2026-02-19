package it.pagopa.touchpoint.jwtissuerservice.services

import it.pagopa.touchpoint.jwtissuerservice.models.PrivateKeyWithKid
import it.pagopa.touchpoint.jwtissuerservice.models.PublicKeyWithKid
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.*
import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

@Component
@Profile("local")
class InMemorySecurityKeysService : IReactiveSecurityKeysService {

    private val logger = LoggerFactory.getLogger(javaClass)
    private val kid: String
    private val ecPrivateKey: ECPrivateKey
    private val ecPublicKey: ECPublicKey

    init {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = keyPairGenerator.generateKeyPair()
        ecPrivateKey = keyPair.private as ECPrivateKey
        ecPublicKey = keyPair.public as ECPublicKey

        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(ecPublicKey.encoded)
        kid = Base64.getUrlEncoder().withoutPadding().encodeToString(hash)

        logger.info("InMemorySecurityKeysService initialized with kid: {}", kid)
    }

    override fun getPrivate(): Mono<PrivateKeyWithKid> {
        return Mono.just(PrivateKeyWithKid(kid, ecPrivateKey))
    }

    override fun getPublic(): Flux<PublicKeyWithKid> {
        return Flux.just(PublicKeyWithKid(kid, ecPublicKey))
    }
}
