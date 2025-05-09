ARG ALPINE_VERSION=3.21
FROM alpine:${ALPINE_VERSION}

# Install packages
RUN apk add --no-cache tzdata nginx

STOPSIGNAL SIGQUIT

EXPOSE 80
EXPOSE 443

CMD ["/usr/sbin/nginx", "-g", "daemon off;"]
