package it.pagopa.touchpoint.jwtissuerservice.models

import java.io.Serializable
import java.security.PrivateKey

data class PrivateKeyWithKid(val kid: String, val privateKey: PrivateKey) : Serializable
