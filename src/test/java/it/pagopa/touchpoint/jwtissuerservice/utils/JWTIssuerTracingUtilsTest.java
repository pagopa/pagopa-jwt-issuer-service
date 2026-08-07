package it.pagopa.touchpoint.jwtissuerservice.utils;

import it.pagopa.touchpoint.jwtissuerservice.mdcutilities.JWTIssuerTracingUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import reactor.util.context.Context;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JWTIssuerTracingUtilsTest {

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void shouldReturnSameContextWhenTracingEntriesAreNull() {
        // prerequisite
        Context reactorContext = Context.of("existing-key", "existing-value");

        // test
        Context enrichedContext = JWTIssuerTracingUtils
                .enrichContextForJwtIssuer(null, null, null, null, null, reactorContext);

        // assertions
        assertSame(reactorContext, enrichedContext);
        assertEquals("existing-value", enrichedContext.get("existing-key"));
    }

    @Test
    void shouldPreserveExistingContextEntriesWhenEnriching() {
        // prerequisite
        Context existingContext = Context.of("pre-existing-key", "pre-existing-value");
        Map<JWTIssuerTracingUtils.TracingEntry, String> tracingEntries = Map.of(
                JWTIssuerTracingUtils.TracingEntry.CTX_TRANSACTION_ID,
                "transaction-id"
        );

        // test
        Context enrichedContext = JWTIssuerTracingUtils.enrichContextForJwtIssuer(tracingEntries, existingContext);

        // assertions
        assertEquals("pre-existing-value", enrichedContext.get("pre-existing-key"));
        assertEquals(
                "transaction-id",
                enrichedContext.get(JWTIssuerTracingUtils.TracingEntry.CTX_TRANSACTION_ID.getKey())
        );
    }

    @Test
    void shouldExposeExpectedTracingEntryKeys() {
        assertEquals("ctx.transaction.id", JWTIssuerTracingUtils.TracingEntry.CTX_TRANSACTION_ID.getKey());
        assertEquals("ctx.wallet.id", JWTIssuerTracingUtils.TracingEntry.CTX_WALLET_ID.getKey());
        assertEquals("ctx.rpt.ids", JWTIssuerTracingUtils.TracingEntry.CTX_RPT_IDS.getKey());
        assertEquals("ctx.payment.tokens", JWTIssuerTracingUtils.TracingEntry.CTX_PAYMENT_TOKENS.getKey());
        assertEquals("dependency", JWTIssuerTracingUtils.TracingEntry.DEPENDENCY.getKey());
        assertEquals("error.type", JWTIssuerTracingUtils.TracingEntry.ERROR_TYPE.getKey());
        assertEquals("error.message", JWTIssuerTracingUtils.TracingEntry.ERROR_MESSAGE.getKey());
    }

    @Test
    void shouldExposeExpectedTracingEntryDefaultValues() {
        assertEquals("ctx.transaction.id", JWTIssuerTracingUtils.TracingEntry.CTX_TRANSACTION_ID.getKey());
        assertEquals("ctx.wallet.id", JWTIssuerTracingUtils.TracingEntry.CTX_WALLET_ID.getKey());
        assertEquals("ctx.rpt.ids", JWTIssuerTracingUtils.TracingEntry.CTX_RPT_IDS.getKey());
        assertEquals("ctx.payment.tokens", JWTIssuerTracingUtils.TracingEntry.CTX_PAYMENT_TOKENS.getKey());
        assertEquals("{errorType-not-found}", JWTIssuerTracingUtils.TracingEntry.ERROR_TYPE.getDefaultValue());
        assertEquals("{errorMessage-not-found}", JWTIssuerTracingUtils.TracingEntry.ERROR_MESSAGE.getDefaultValue());
    }

    @Test
    void shouldPopulateAndCleanupMdcForErrorDetails() {
        // prerequisite
        RuntimeException error = new RuntimeException("error");
        String dependency = "dep";

        // test
        JWTIssuerTracingUtils.withErrorMdc(
                error,
                Map.of(JWTIssuerTracingUtils.TracingEntry.DEPENDENCY.getKey(), dependency),
                () -> {
                    assertEquals(
                            RuntimeException.class.getName(),
                            MDC.get(JWTIssuerTracingUtils.TracingEntry.ERROR_TYPE.getKey())
                    );
                    assertEquals("error", MDC.get(JWTIssuerTracingUtils.TracingEntry.ERROR_MESSAGE.getKey()));
                    assertEquals(dependency, MDC.get(JWTIssuerTracingUtils.TracingEntry.DEPENDENCY.getKey()));
                }
        );

        // assertions
        assertNull(MDC.get(JWTIssuerTracingUtils.TracingEntry.ERROR_TYPE.getKey()));
        assertNull(MDC.get(JWTIssuerTracingUtils.TracingEntry.ERROR_MESSAGE.getKey()));
        assertNull(MDC.get(JWTIssuerTracingUtils.TracingEntry.DEPENDENCY.getKey()));
    }

    @Test
    void shouldUseFallbackValuesForNullThrowable() {
        // test
        JWTIssuerTracingUtils.withErrorMdc(null, () -> {
            assertEquals(
                    "{errorType-not-found}",
                    MDC.get(JWTIssuerTracingUtils.TracingEntry.ERROR_TYPE.getKey())
            );
            assertEquals(
                    "{errorMessage-not-found}",
                    MDC.get(JWTIssuerTracingUtils.TracingEntry.ERROR_MESSAGE.getKey())
            );
        });
    }

    @Test
    void shouldUseDefaultMessageWhenThrowableMessageIsNull() {
        // test
        JWTIssuerTracingUtils.withErrorMdc(
                new RuntimeException((String) null),
                () -> assertEquals(
                        "{errorMessage-not-found}",
                        MDC.get(JWTIssuerTracingUtils.TracingEntry.ERROR_MESSAGE.getKey())
                )
        );
    }

    @Test
    void shouldCleanupMdcEvenWhenWithErrorMdcBlockThrows() {
        // prerequisite
        RuntimeException expected = new RuntimeException("failing-block");
        IllegalStateException error = new IllegalStateException("error");
        Map<String, String> attributes = Map.of(
                JWTIssuerTracingUtils.TracingEntry.DEPENDENCY.getKey(),
                "depValue"
        );
        Runnable block = () -> {
            throw expected;
        };

        // test & assertions
        RuntimeException thrown = assertThrows(
                RuntimeException.class,
                () -> JWTIssuerTracingUtils.withErrorMdc(error, attributes, block)
        );
        assertSame(expected, thrown);
        assertNull(MDC.get(JWTIssuerTracingUtils.TracingEntry.ERROR_TYPE.getKey()));
        assertNull(MDC.get(JWTIssuerTracingUtils.TracingEntry.ERROR_MESSAGE.getKey()));
        assertNull(MDC.get(JWTIssuerTracingUtils.TracingEntry.DEPENDENCY.getKey()));
    }

    @Test
    void shouldIgnoreNullAttributesInWithErrorMdc() {
        // prerequisite
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("valid.key", "value");
        attributes.put(null, "ignored-value");
        attributes.put("null.value", null);

        // test
        JWTIssuerTracingUtils.withErrorMdc(new RuntimeException("error"), attributes, () -> {
            assertEquals("value", MDC.get("valid.key"));
            assertNull(MDC.get("null.value"));
        });

        // assertions
        assertNull(MDC.get("valid.key"));
    }

    @Test
    void shouldWorkWhenErrorAttributesMapIsNull() {
        // test
        JWTIssuerTracingUtils.withErrorMdc(
                new RuntimeException("error"),
                null,
                () -> assertEquals(
                        RuntimeException.class.getName(),
                        MDC.get(JWTIssuerTracingUtils.TracingEntry.ERROR_TYPE.getKey())
                )
        );
    }

    @Test
    void shouldPopulateAndCleanupMdcForContextDetails() {
        // test
        JWTIssuerTracingUtils.withContextDetailsMdc(
                Map.of("detail", "value"),
                Map.of(JWTIssuerTracingUtils.TracingEntry.CTX_WALLET_ID.getKey(), "/transactions"),
                () -> {
                    assertTrue(MDC.get("ctx.details").contains("\"detail\":\"value\""));
                    assertEquals("/transactions", MDC.get(JWTIssuerTracingUtils.TracingEntry.CTX_WALLET_ID.getKey()));
                }
        );

        // assertions
        assertNull(MDC.get("ctx.details"));
        assertNull(MDC.get(JWTIssuerTracingUtils.TracingEntry.CTX_WALLET_ID.getKey()));
    }

    @Test
    void shouldPopulateContextDetailsFromSingleArgumentOverload() {
        // test
        JWTIssuerTracingUtils.withContextDetailsMdc(Map.of("status", "CLOSED"), () -> {
            String details = MDC.get("ctx.details");
            assertNotNull(details);
            assertTrue(details.contains("\"status\":\"CLOSED\""));
        });
    }

    @Test
    void shouldPopulateEmptyJsonWhenDetailsAreNull() {
        // test
        JWTIssuerTracingUtils.withContextDetailsMdc(null, () -> assertEquals("{}", MDC.get("ctx.details")));

        // assertions
        assertNull(MDC.get("ctx.details"));
    }

    @Test
    void shouldPopulateEmptyJsonWhenDetailsAreEmpty() {
        // test
        JWTIssuerTracingUtils.withContextDetailsMdc(Map.of(), () -> assertEquals("{}", MDC.get("ctx.details")));

        // assertions
        assertNull(MDC.get("ctx.details"));
    }

    @Test
    void shouldIgnoreNullAttributesInWithContextDetailsMdc() {
        // prerequisite
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("present", "yes");
        attributes.put("absent", null);

        // test
        JWTIssuerTracingUtils.withContextDetailsMdc(
                Map.of("k", "v"),
                attributes,
                () -> {
                    assertEquals("yes", MDC.get("present"));
                    assertNull(MDC.get("absent"));
                }
        );

        // assertions
        assertNull(MDC.get("present"));
    }

    @Test
    void shouldWorkWhenContextDetailsAttributesMapIsNull() {
        // test
        JWTIssuerTracingUtils.withContextDetailsMdc(
                Map.of("transactionId", "event"),
                null,
                () -> {
                    String details = MDC.get("ctx.details");
                    assertNotNull(details);
                    assertTrue(details.contains("\"transactionId\":\"event\""));
                }
        );
    }

    @Test
    void shouldCleanupMdcEvenWhenWithContextDetailsBlockThrows() {
        // prerequisite
        RuntimeException expected = new RuntimeException("failing-context-details");
        Map<String, String> details = Map.of("detail", "value");
        Map<String, String> attributes = Map.of(
                JWTIssuerTracingUtils.TracingEntry.CTX_TRANSACTION_ID.getKey(),
                "/transactions"
        );
        Runnable block = () -> {
            throw expected;
        };

        // test & assertions
        RuntimeException thrown = assertThrows(
                RuntimeException.class,
                () -> JWTIssuerTracingUtils.withContextDetailsMdc(details, attributes, block)
        );
        assertSame(expected, thrown);
        assertNull(MDC.get("ctx.details"));
        assertNull(MDC.get(JWTIssuerTracingUtils.TracingEntry.CTX_TRANSACTION_ID.getKey()));
    }
}
