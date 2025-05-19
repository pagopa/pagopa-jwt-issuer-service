package it.pagopa.touchpoint.jwtissuerservice.services

import it.pagopa.touchpoint.jwtissuerservice.models.PrivateKeyWithKid
import it.pagopa.touchpoint.jwtissuerservice.models.PublicKeyWithKid
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

interface IReactiveSecurityKeysService {
    fun getPublic(): Flux<PublicKeyWithKid>

    fun getPrivate(): Mono<PrivateKeyWithKid>
}
