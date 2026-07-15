package com.antirat.guard;

import com.antirat.AntiRatRuntime;
import com.antirat.model.ThreatEvent;
import com.antirat.model.ThreatType;
import com.antirat.scan.ModIdentity;
import com.antirat.scan.ModIndex;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

final class GuardedProxySelector extends ProxySelector {
    private static final long REPORT_SUPPRESS_MS = 15_000L;

    private final ProxySelector delegate;
    private final Map<String, Long> lastReportAt = new ConcurrentHashMap<>();

    GuardedProxySelector(ProxySelector delegate) {
        this.delegate = delegate;
    }

    @Override
    public List<Proxy> select(URI uri) {
        if (uri != null) {
            ModIdentity source = ModIndex.findByCurrentStack();
            NetworkDecision decision = SensitiveNetworkPolicy.classify(uri, source);
            if (decision.report() && shouldReport(uri, source, decision)) {
                AntiRatRuntime.report(ThreatEvent.create(
                        ThreatType.NETWORK_REQUEST,
                        decision.riskLevel(),
                        decision.title(),
                        decision.summary(),
                        source.id(),
                        source.name(),
                        source.id().equals("unknown") ? "" : source.id(),
                        sanitizeTarget(uri),
                        decision.block(),
                        decision.accuracy(),
                        decision.tip(),
                        decision.evidence()
                ));
            }

            if (decision.block()) {
                throw new SecurityException("AntiRat blocked outbound request to " + sanitizeTarget(uri));
            }
        }

        if (delegate != null) {
            return delegate.select(uri);
        }
        return List.of(Proxy.NO_PROXY);
    }

    @Override
    public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
        if (delegate != null) {
            delegate.connectFailed(uri, sa, ioe);
            return;
        }
        if (sa instanceof InetSocketAddress inetSocketAddress) {
            AntiRatRuntime.LOGGER.debug("Connection failed for {} via {}", uri, inetSocketAddress);
        }
    }

    private boolean shouldReport(URI uri, ModIdentity source, NetworkDecision decision) {
        long now = System.currentTimeMillis();
        String key = source.id() + "|" + decision.title() + "|" + uri.getHost();
        Long previous = lastReportAt.put(key, now);
        return previous == null || now - previous > REPORT_SUPPRESS_MS;
    }

    static String sanitizeTarget(URI uri) {
        StringBuilder builder = new StringBuilder();
        if (uri.getScheme() != null) {
            builder.append(uri.getScheme()).append("://");
        }
        if (uri.getHost() != null) {
            builder.append(uri.getHost());
        }
        if (uri.getRawPath() != null && !uri.getRawPath().isBlank()) builder.append("/<redacted-path>");
        if (uri.getRawQuery() != null && !uri.getRawQuery().isBlank()) {
            builder.append("?<redacted>");
        }
        return builder.toString();
    }
}
