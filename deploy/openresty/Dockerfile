# Minimal OpenResty image that bakes this config in. Pair with the Go
# binary built from cmd/sso-server in a docker-compose / k8s manifest.
FROM openresty/openresty:1.25.3.2-1-alpine

# Copy config + Lua sources into the conventional OpenResty prefix.
COPY nginx.conf       /usr/local/openresty/nginx/conf/nginx.conf
COPY conf.d/          /usr/local/openresty/nginx/conf/conf.d/
COPY lua/             /usr/local/openresty/nginx/lua/

# Generate a self-signed cert at build time so the dev listener works
# out of the box. Replace with a mount-binding the real cert in prod.
RUN mkdir -p /usr/local/openresty/nginx/conf/ssl && \
    apk add --no-cache openssl && \
    openssl req -x509 -newkey ed25519 -nodes \
        -keyout /usr/local/openresty/nginx/conf/ssl/dev.key \
        -out    /usr/local/openresty/nginx/conf/ssl/dev.crt \
        -days 30 -subj "/CN=sso.local"

EXPOSE 8443
CMD ["openresty", "-g", "daemon off;"]
