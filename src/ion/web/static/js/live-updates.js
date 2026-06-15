/* live-updates.js (v0.39.9)
 * SSE-backed live updates with automatic setInterval polling fallback.
 *
 * Replaces per-page `setInterval(loadX, ms)` pollers with a single long-lived
 * EventSource per browser tab. The server (see ion/services/event_stream.py)
 * emits a `refresh` event when a topic's state changes; we respond by calling
 * the page's existing fetch routine. If SSE is unavailable — no EventSource,
 * the endpoint is disabled (503), the session is invalid (401), or the
 * connection is permanently lost — we transparently fall back to polling so
 * behaviour is never worse than before.
 *
 * Usage:
 *   const stop = ionLiveUpdates('investigations', () => { iqLoad(); }, 10000);
 *   // later, e.g. on teardown: stop();
 */
(function () {
  'use strict';

  function ionLiveUpdates(topic, onRefresh, fallbackMs) {
    var es = null;
    var pollTimer = null;
    var stopped = false;
    var interval = fallbackMs && fallbackMs > 0 ? fallbackMs : 30000;

    function startPolling() {
      if (pollTimer || stopped) return;
      pollTimer = setInterval(function () {
        if (!stopped) {
          try { onRefresh(); } catch (e) { /* swallow — next tick retries */ }
        }
      }, interval);
    }

    function stopPolling() {
      if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    }

    function stop() {
      stopped = true;
      if (es) { try { es.close(); } catch (e) {} es = null; }
      stopPolling();
    }

    // No EventSource support (very old browsers) — poll and bail.
    if (typeof EventSource === 'undefined') {
      startPolling();
      return stop;
    }

    try {
      es = new EventSource('/api/events/stream?topic=' + encodeURIComponent(topic));
    } catch (e) {
      startPolling();
      return stop;
    }

    es.addEventListener('refresh', function () {
      if (!stopped) {
        try { onRefresh(); } catch (e) { /* swallow */ }
      }
    });

    // SSE is healthy — cancel any fallback poller that was started during a
    // transient outage.
    es.onopen = function () {
      stopPolling();
    };

    es.onerror = function () {
      // EventSource auto-reconnects while readyState === CONNECTING. It only
      // reaches CLOSED on a hard failure (503 disabled / 401 unauth / blocked).
      // In that case give the user polling instead of going dark.
      if (es && es.readyState === EventSource.CLOSED) {
        startPolling();
      }
    };

    return stop;
  }

  window.ionLiveUpdates = ionLiveUpdates;
})();
