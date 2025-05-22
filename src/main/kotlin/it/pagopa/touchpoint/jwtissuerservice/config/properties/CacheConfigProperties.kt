package it.pagopa.touchpoint.jwtissuerservice.config.properties

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("key-store.cache")
data class CacheConfigProperties(val maxSize: Long, val ttlMins: Long)
