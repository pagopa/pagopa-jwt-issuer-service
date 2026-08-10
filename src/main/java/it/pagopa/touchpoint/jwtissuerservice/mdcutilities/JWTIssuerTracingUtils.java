package it.pagopa.touchpoint.jwtissuerservice.mdcutilities;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.MDC;
import reactor.util.context.Context;

import java.util.*;

public class JWTIssuerTracingUtils {
    private static final String CTX_DETAILS_KEY = "ctx.details";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private JWTIssuerTracingUtils() {
    }

    /**
     * Tracing keys used in MDC and/or propagated from Reactor Context.
     *
     * <p>
     * Entries marked as {@code contextBound = true} are copied from Reactor Context
     * to MDC by {@link MDCContextLifter}. Entries marked as {@code false} are
     * written locally in MDC (for example by {@link #withErrorMdc}).
     */
    public enum TracingEntry {
        CTX_TRANSACTION_ID("ctx.transaction.id", "{transactionId-not-found}", true),
        CTX_AUTHORIZATION_REQUEST_ID("ctx.authorization.request.id", "{authorizationRequestId-not-found}", true),
        CTX_WALLET_ID("ctx.wallet.id", "{walletId-not-found}", true),
        DEPENDENCY("dependency", "{dependency-not-found}", false),
        ERROR_TYPE("error.type", "{errorType-not-found}", false),
        ERROR_MESSAGE("error.message", "{errorMessage-not-found}", false);

        private final String key;
        private final String defaultValue;
        private final boolean contextBound;

        TracingEntry(
                String key,
                String defaultValue,
                boolean contextBound
        ) {
            this.key = key;
            this.defaultValue = defaultValue;
            this.contextBound = contextBound;
        }

        public String getKey() {
            return key;
        }

        public String getDefaultValue() {
            return defaultValue;
        }

        public boolean isContextBound() {
            return contextBound;
        }
    }

    /**
     * Enrich Reactor Context with tracing entries in a fully generic way.
     *
     * <p>
     * This method accepts a map of {@link TracingEntry} enum keys with their
     * corresponding values. Each entry is added to the context with its value or
     * default value if null. Any future TracingEntry additions are automatically
     * supported without method changes.
     *
     * @param tracingEntries map of TracingEntry to value; null values use defaults
     * @param reactorContext the context to enrich
     * @return enriched context with all tracing entries
     */
    public static Context enrichContextForJwtIssuer(
                                                    Map<TracingEntry, String> tracingEntries,
                                                    Context reactorContext
    ) {
        Context enrichedContext = reactorContext;
        if (tracingEntries != null) {
            for (Map.Entry<TracingEntry, String> entry : tracingEntries.entrySet()) {
                enrichedContext = enrichedContext.put(
                        entry.getKey().getKey(),
                        entry.getValue() != null
                                ? entry.getValue()
                                : entry.getKey().getDefaultValue()
                );
            }
        }
        return enrichedContext;
    }

    /** Enrich Reactor Context with JwtIssuer metadata used by MDC/logging hooks. */
    public static Context enrichContextForJwtIssuer(
                                                    String transactionId,
                                                    String orderId,
                                                    String walletId,
                                                    Context reactorContext
    ) {

        Map<TracingEntry, String> tracingEntries = new HashMap<>();
        if (transactionId != null) {
            tracingEntries.put(
                    TracingEntry.CTX_TRANSACTION_ID,
                    transactionId
            );
        }
        if (orderId != null) {
            tracingEntries.put(
                    TracingEntry.CTX_AUTHORIZATION_REQUEST_ID,
                    orderId
            );
        }
        if (walletId != null) {
            tracingEntries.put(
                    TracingEntry.CTX_WALLET_ID,
                    walletId
            );
        }

        return enrichContextForJwtIssuer(tracingEntries, reactorContext);
    }

    /**
     * Executes a block with error attributes ({@code error.type} and
     * {@code error.message}) and an arbitrary map of top-level attributes
     * temporarily stored in MDC.
     *
     * <p>
     * Error attributes are extracted from the provided {@link Throwable}. Top-level
     * attributes are passed to MDC cleanup logic where string conversion is
     * handled. All keys are guaranteed to be removed after block execution.
     *
     * @param error      the exception to extract type and message from (can be
     *                   null)
     * @param attributes map of top-level MDC key-value attributes (can be null)
     * @param block      code to execute while attributes are available in MDC
     */
    public static void withErrorMdc(
                                    Throwable error,
                                    Map<String, ?> attributes,
                                    Runnable block
    ) {
        Map<String, Object> mdcMap = new HashMap<>();

        mdcMap.put(
                TracingEntry.ERROR_TYPE.getKey(),
                error != null
                        ? error.getClass().getName()
                        : TracingEntry.ERROR_TYPE.getDefaultValue()
        );
        mdcMap.put(
                TracingEntry.ERROR_MESSAGE.getKey(),
                error != null && error.getMessage() != null
                        ? error.getMessage()
                        : TracingEntry.ERROR_MESSAGE.getDefaultValue()
        );

        if (attributes != null) {
            attributes.forEach(
                    (
                     key,
                     value
                    ) -> {
                        if (key != null && value != null) {
                            mdcMap.put(key, value);
                        }
                    }
            );
        }

        insertIntoMdcAndCleanup(mdcMap, block);
    }

    /**
     * Executes a block with structured error details temporarily inserted in MDC.
     *
     * <p>
     * The method adds {@code error.type} and {@code error.message} keys, executes
     * the provided block, and always removes those keys afterward.
     *
     * @param error error instance used to populate MDC metadata
     * @param block code to execute while error metadata is available in MDC
     */
    public static void withErrorMdc(
                                    Throwable error,
                                    Runnable block
    ) {
        withErrorMdc(error, null, block);
    }

    /**
     * Executes a block with {@code ctx.details} temporarily stored in MDC as a JSON
     * string.
     *
     * <p>
     * The input map is serialized to raw JSON and stored under key
     * {@code ctx.details}. If serialization fails, an empty JSON object
     * ({@code {}}) is used as fallback. The key is always removed after block
     * execution.
     *
     * @param details map of detail values to serialize under {@code ctx.details}
     * @param block   code to execute while {@code ctx.details} is available in MDC
     */
    public static void withContextDetailsMdc(
                                             Map<String, ?> details,
                                             Runnable block
    ) {
        withContextDetailsMdc(details, null, block);
    }

    /**
     * Executes a block with {@code ctx.details} temporarily stored in MDC as a JSON
     * string.
     *
     * <p>
     * The input map is serialized to raw JSON and stored under key
     * {@code ctx.details}. If serialization fails, an empty JSON object
     * ({@code {}}) is used as fallback. The key is always removed after block
     * execution.
     *
     * @param details map of detail values to serialize under {@code ctx.details}
     * @param block   code to execute while {@code ctx.details} is available in MDC
     */
    public static void withContextDetailsMdc(
                                             Map<String, ?> details,
                                             Map<String, ?> attributes,
                                             Runnable block
    ) {
        Map<String, Object> mdcMap = new HashMap<>();

        String rawDetails = "{}";
        if (details != null) {
            try {
                rawDetails = OBJECT_MAPPER.writeValueAsString(details);
            } catch (JsonProcessingException ignored) {
                rawDetails = "{}";
            }
        }
        mdcMap.put(CTX_DETAILS_KEY, rawDetails);

        if (attributes != null) {
            attributes.forEach(
                    (
                     k,
                     v
                    ) -> {
                        if (k != null && v != null) {
                            mdcMap.put(k, v);
                        }
                    }
            );
        }

        insertIntoMdcAndCleanup(mdcMap, block);
    }

    /**
     * Inserts the provided entries into MDC, executes the given block, and always
     * removes the inserted keys afterward.
     *
     * <p>
     * This method guarantees MDC cleanup through a {@code finally} block, so
     * temporary values do not leak across log statements or threads.
     *
     * @param entries key/value pairs to temporarily add to MDC
     * @param block   code to execute while MDC entries are available
     */
    private static void insertIntoMdcAndCleanup(
                                                Map<String, ?> entries,
                                                Runnable block
    ) {
        List<String> detailKeys = new ArrayList<>();

        try {
            if (entries != null) {
                entries.forEach(
                        (
                         key,
                         value
                        ) -> {
                            if (key != null && value != null) {
                                MDC.put(key, value.toString());
                                detailKeys.add(key);
                            }
                        }
                );
            }
            block.run();
        } finally {
            detailKeys.forEach(MDC::remove);
        }
    }
}
