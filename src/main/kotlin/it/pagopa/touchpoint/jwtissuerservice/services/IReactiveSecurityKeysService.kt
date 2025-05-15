package it.pagopa.touchpoint.jwtissuerservice.services

import java.security.PrivateKey
import java.security.PublicKey
import reactor.core.publisher.Mono

interface IReactiveSecurityKeysService {
    fun getPublic(): Mono<PublicKey>

    fun getPrivate(): Mono<PrivateKey>
}
