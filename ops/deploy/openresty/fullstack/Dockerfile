FROM openresty/openresty:1.25.3.2-1-alpine

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY conf.d/ /usr/local/openresty/nginx/conf/conf.d/
COPY lua/ /usr/local/openresty/nginx/lua/
COPY static/landing/ /srv/landing/
COPY static/console/ /srv/console/
COPY static/docs/ /srv/docs/
COPY static/sample/ /srv/sample/

EXPOSE 8080

USER 65532:65532
ENTRYPOINT ["/usr/local/openresty/bin/openresty"]
CMD ["-g", "daemon off;"]
