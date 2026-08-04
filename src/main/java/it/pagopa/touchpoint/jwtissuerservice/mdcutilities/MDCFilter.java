package it.pagopa.touchpoint.jwtissuerservice.mdcutilities;

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import java.util.ArrayList;
import java.util.Optional;

@Component
public class MDCFilter implements WebFilter {

    public static final String HEADER_TRANSACTION_ID = "x-transaction-id";
    public static final String HEADER_WALLET_ID = "x-wallet-id";
    public static final String HEADER_RPT_ID = "x-rpt-ids";

    @Override
    public Mono<Void> filter(
                             ServerWebExchange exchange,
                             WebFilterChain chain
    ) {
        final HttpHeaders headers = exchange.getRequest().getHeaders();
        final String transactionId = Optional.ofNullable(headers.get(HEADER_TRANSACTION_ID)).orElse(new ArrayList<>())
                .stream()
                .findFirst().orElse(JWTIssuerTracingUtils.TracingEntry.CTX_TRANSACTION_ID.getDefaultValue());
        final String walletId = Optional.ofNullable(headers.get(HEADER_WALLET_ID)).orElse(new ArrayList<>())
                .stream()
                .findFirst().orElse(JWTIssuerTracingUtils.TracingEntry.CTX_WALLET_ID.getDefaultValue());
        final String rptId = Optional.ofNullable(headers.get(HEADER_RPT_ID)).orElse(new ArrayList<>()).stream()
                .findFirst().orElse(JWTIssuerTracingUtils.TracingEntry.CTX_RPT_IDS.getDefaultValue());

        return chain.filter(exchange)
                .contextWrite(Context.of(JWTIssuerTracingUtils.TracingEntry.CTX_TRANSACTION_ID.getKey(), transactionId))
                .contextWrite(Context.of(JWTIssuerTracingUtils.TracingEntry.CTX_WALLET_ID.getKey(), walletId))
                .contextWrite(Context.of(JWTIssuerTracingUtils.TracingEntry.CTX_RPT_IDS.getKey(), rptId));
    }
}
