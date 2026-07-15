package com.antirat.guard;

import com.antirat.AntiRatRuntime;
import com.antirat.model.RiskLevel;
import com.antirat.model.ThreatEvent;
import com.antirat.model.ThreatType;
import com.antirat.scan.ModIdentity;
import com.antirat.scan.ModIndex;

import java.io.IOException;
import java.net.CookieHandler;
import java.net.URI;
import java.util.List;
import java.util.Map;

final class GuardedCookieHandler extends CookieHandler {
    private final CookieHandler delegate;

    GuardedCookieHandler(CookieHandler delegate) {
        this.delegate = delegate;
    }

    @Override
    public Map<String, List<String>> get(URI uri, Map<String, List<String>> requestHeaders) throws IOException {
        if (uri != null) {
            ModIdentity source = ModIndex.findByCurrentStack();
            NetworkDecision decision = SensitiveNetworkPolicy.classify(uri, source);
            if (decision.block()) {
                AntiRatRuntime.report(ThreatEvent.create(
                        ThreatType.COOKIE_ACCESS,
                        RiskLevel.HIGH,
                        "Blocked cookies to suspicious endpoint",
                        "AntiRat refused to attach client cookies to a high-risk destination.",
                        source.id(),
                        source.name(),
                        "",
                        uri.getHost(),
                        true,
                        84,
                        "Cookies can become account material when sent to the wrong endpoint.",
                        decision.evidence()
                ));
                return Map.of();
            }
        }
        return delegate == null ? Map.of() : delegate.get(uri, requestHeaders);
    }

    @Override
    public void put(URI uri, Map<String, List<String>> responseHeaders) throws IOException {
        if (delegate != null) {
            delegate.put(uri, responseHeaders);
        }
    }
}
