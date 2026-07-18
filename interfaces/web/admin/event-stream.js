/**
 * event-stream.js — SSE connection manager for the Security Events tab.
 *
 * Manages a single EventSource connection with automatic reconnection,
 * Last-Event-ID tracking for resuming missed events, and event type
 * filtering. The connection is established lazily when the Security
 * Events page is first shown and torn down when navigating away, so
 * idle dashboards don't count against the browser's per-domain
 * EventSource limit (typically 6).
 *
 * The stream URL is /api/v1/admin/events/stream; authentication is
 * inherited from the page's fetch-based login (the cookie/session
 * the admin SPA established).
 */
(function (exports) {
  'use strict';

  var STREAM_URL = '/api/v1/admin/events/stream';

  // ---- Connection state ----
  var es = null;          // active EventSource (null when disconnected)
  var lastEventID = 0;    // monotonic id from the stream's `id:` field
  var isConnected = false;
  var reconnectTimer = null;
  var reconnectDelay = 1000; // ms, doubles on each failure (exponential backoff)
  var maxReconnectDelay = 30000; // 30s cap

  // ---- Callbacks ----
  var onEvent = null;     // function(type, data, id)
  var onStatus = null;    // function(connected)

  /**
   * Start the SSE stream. If already connected, this is a no-op.
   * @param {function(string, object, number)} eventCb — called per event
   * @param {function(boolean)} statusCb — called when connection state changes
   */
  function connect(eventCb, statusCb) {
    onEvent = eventCb;
    onStatus = statusCb;

    if (es) {
      return; // already connected
    }
    openConnection();
  }

  function openConnection() {
    if (es) {
      es.close();
      es = null;
    }

    var url = STREAM_URL;
    if (lastEventID > 0) {
      url += '?lastEventID=' + lastEventID;
    }

    es = new EventSource(url);

    es.onopen = function () {
      isConnected = true;
      reconnectDelay = 1000; // reset backoff on successful connection
      if (onStatus) onStatus(true);
    };

    es.onmessage = function (msg) {
      // Generic message handler for events without a specific `event:` field.
      // Most events carry an explicit type, so this is a fallback.
      try {
        var data = JSON.parse(msg.data);
        var eventID = parseInt(msg.lastEventId, 10) || 0;
        if (eventID > lastEventID) {
          lastEventID = eventID;
        }
        if (onEvent) onEvent('message', data, eventID);
      } catch (e) {
        // Ignore malformed frames
      }
    };

    es.addEventListener('login', makeHandler('login'));
    es.addEventListener('token', makeHandler('token'));
    es.addEventListener('consent', makeHandler('consent'));
    es.addEventListener('admin', makeHandler('admin'));
    es.addEventListener('anomaly', makeHandler('anomaly'));

    es.onerror = function () {
      isConnected = false;
      if (onStatus) onStatus(false);

      // Close failed connection before retry
      if (es) {
        es.close();
        es = null;
      }

      // Exponential backoff reconnection
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }
      reconnectTimer = setTimeout(function () {
        reconnectTimer = null;
        openConnection();
      }, reconnectDelay);

      reconnectDelay = Math.min(reconnectDelay * 2, maxReconnectDelay);
    };
  }

  function makeHandler(eventType) {
    return function (msg) {
      try {
        var data = JSON.parse(msg.data);
        var eventID = parseInt(msg.lastEventId, 10) || 0;
        if (eventID > lastEventID) {
          lastEventID = eventID;
        }
        if (onEvent) onEvent(eventType, data, eventID);
      } catch (e) {
        // Ignore malformed frames
      }
    };
  }

  /**
   * Disconnect the SSE stream. Call when navigating away from the
   * Security Events page to free the EventSource slot.
   */
  function disconnect() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    if (es) {
      es.close();
      es = null;
    }
    isConnected = false;
    if (onStatus) onStatus(false);
    onEvent = null;
    onStatus = null;
  }

  /**
   * Reset the stream position. Call after a page navigation / clear
   * so that a subsequent connect starts fresh (no replay of old events).
   */
  function resetPosition() {
    lastEventID = 0;
  }

  /**
   * Returns true when the EventSource is open and receiving events.
   */
  function connected() {
    return isConnected;
  }

  // Export public API
  exports.SSEStream = {
    connect: connect,
    disconnect: disconnect,
    resetPosition: resetPosition,
    connected: connected
  };
})(window);
