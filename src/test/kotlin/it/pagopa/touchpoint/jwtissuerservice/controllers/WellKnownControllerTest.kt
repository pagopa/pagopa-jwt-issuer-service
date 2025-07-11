package it.pagopa.touchpoint.jwtissuerservice.controllers

import it.pagopa.generated.touchpoint.jwtissuerservice.v1.model.OpenIDDiscoveryResponseDto
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.reactive.server.WebTestClient

@WebFluxTest(WellKnownController::class)
@TestPropertySource(locations = ["classpath:application.test.properties"])
class WellKnownControllerTest {

    @Autowired lateinit var webClient: WebTestClient

    @Test
    fun `Should return openid configuration info successfully`() {
        val expectedResponse =
            OpenIDDiscoveryResponseDto(
                jwksUri = "https://localhost/tokens/keys",
                subjectTypesSupported = listOf("public"),
                tokenEndpoint = "https://localhost/tokens",
                idTokenSigningAlgValuesSupported = listOf("RS256", "ES256"),
                responseTypesSupported = listOf("code"),
                authorizationEndpoint = "https://not-supported",
                issuer = "jwtIssuer",
            )
        webClient
            .get()
            .uri("/.well-known/openid-configuration")
            .exchange()
            .expectStatus()
            .isOk
            .expectBody(OpenIDDiscoveryResponseDto::class.java)
            .consumeWith { assertEquals(expectedResponse, it.responseBody) }
    }
}
