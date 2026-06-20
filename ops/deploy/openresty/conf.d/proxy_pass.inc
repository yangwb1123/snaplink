# Common proxy_pass settings shared across SSO routes. Keeps the per-route
# blocks short.
proxy_pass http://sso_backend;
proxy_http_version 1.1;
proxy_set_header Connection "";
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
# Forward correlation headers verbatim — TracingMiddleware on the SSO side
# preserves any incoming X-Request-Id / Traceparent.
proxy_set_header X-Request-Id $http_x_request_id;
proxy_set_header Traceparent $http_traceparent;
# X-Network is stamped by netpolicy_cache.stamp_header() at server-level
# access_by_lua and re-read here so it appears in the upstream request.
proxy_set_header X-Network $http_x_network;
proxy_pass_request_headers on;
proxy_read_timeout 30s;
