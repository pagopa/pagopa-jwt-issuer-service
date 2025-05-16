package it.pagopa.touchpoint.jwtissuerservice.config

import com.github.benmanes.caffeine.cache.Caffeine
import it.pagopa.touchpoint.jwtissuerservice.config.properties.CacheConfigProperties
import java.util.*
import java.util.concurrent.TimeUnit
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.cache.CacheManager
import org.springframework.cache.annotation.EnableCaching
import org.springframework.cache.caffeine.CaffeineCacheManager
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
@EnableCaching
class CacheConfig(@Autowired private val cacheConfigProperties: CacheConfigProperties) {

    @Bean
    fun caffeineCacheManager(caffeine: Caffeine<Any, Any>): CacheManager {
        val caffeineCacheManager = CaffeineCacheManager()
        caffeineCacheManager.setCaffeine(caffeine)
        caffeineCacheManager.setCacheNames(Collections.singleton(cacheConfigProperties.name))
        caffeineCacheManager.setAsyncCacheMode(true)
        caffeineCacheManager.isAllowNullValues = false
        return caffeineCacheManager
    }

    @Bean
    fun caffeineCacheBuilder(): Caffeine<Any, Any> {
        return Caffeine.newBuilder()
            .expireAfterWrite(cacheConfigProperties.ttlMins, TimeUnit.MINUTES)
            .maximumSize(cacheConfigProperties.maxSize)
    }
}
