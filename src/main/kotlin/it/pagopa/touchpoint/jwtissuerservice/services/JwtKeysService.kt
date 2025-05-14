package it.pagopa.touchpoint.jwtissuerservice.services

import com.azure.security.keyvault.keys.KeyClient
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.security.KeyPair

@Component
class JwtKeysService(private val keyClient: KeyClient,
                     @Value("\${jwt.key.name}")
                     private val jwtKeyName: String) {

    fun getKey(): KeyPair {
        return keyClient.getKey(jwtKeyName).key.toRsa()
    }
}