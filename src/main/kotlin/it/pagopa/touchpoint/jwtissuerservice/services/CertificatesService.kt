package it.pagopa.touchpoint.jwtissuerservice.services

import com.azure.security.keyvault.certificates.CertificateAsyncClient
import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.CertificateDetailDto
import it.pagopa.touchpoint.jwtissuerservice.mdcutilities.LogTracingUtils
import java.net.URI
import java.time.Duration
import java.time.OffsetDateTime
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono

@Service
class CertificatesService(private val certClient: CertificateAsyncClient) {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun getCertificateByNameAndValidity(
        certificateName: String,
        validForDays: Int,
    ): Mono<CertificateDetailDto> =
        certClient
            .getCertificate(certificateName)
            .doOnNext {
                LogTracingUtils.loggerTracingUtils()
                    .dependency(LogTracingUtils.AZURE_KEY_VAULT_DEPENDENCY)
                    .details(
                        mapOf(
                            "name" to it.name,
                            "version" to it.properties.version,
                            "enabled" to it.properties.isEnabled?.toString(),
                            "expires_on" to it.properties.expiresOn?.toString(),
                            "not_before" to it.properties.notBefore?.toString(),
                        )
                    )
                    .success()
                    .logInfo(logger, "Retrieved Certificate Properties")
            }
            .filter {
                it.properties.isEnabled &&
                    (it.properties.expiresOn == null ||
                        it.properties.expiresOn.isAfter(
                            OffsetDateTime.now().plus(Duration.ofDays(validForDays.toLong()))
                        ))
            }
            .map {
                CertificateDetailDto(
                    name = it.name,
                    expirationDate = it.properties.expiresOn,
                    updated = it.properties.updatedOn,
                    notBefore = it.properties.notBefore,
                    id = URI(it.properties.id),
                )
            }
}
