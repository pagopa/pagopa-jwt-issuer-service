package it.pagopa.touchpoint.jwtissuerservice.services

import com.azure.security.keyvault.keys.KeyClient
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import org.springframework.beans.factory.annotation.Value
import org.springframework.cache.annotation.Cacheable
import org.springframework.stereotype.Component

@Component
class SecurityKeysService(
    private val keyClient: KeyClient,
    @Value("\${jwt.key.name}") private val jwtKeyName: String,
) {
    @Cacheable("rsaKeys")
    fun getKey(): KeyPair {
        return keyClient.getKey(jwtKeyName).key.toRsa(true)
    }

    fun getPrivate(): PrivateKey {
        return this.getKey().private
    }

    fun getPublic(): PublicKey {
        return this.getKey().public
    }
}
