package it.pagopa.touchpoint.jwtissuerservice.models

import java.io.Serializable
import java.security.PublicKey

data class PublicKeyWithKid(val kid: String, val publicKey: PublicKey) : Serializable
