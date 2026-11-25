ARG ALPINE_VERSION=3.22

FROM alpine:${ALPINE_VERSION} AS base

RUN apk add --no-cache \
    tzdata \
    nginx

STOPSIGNAL SIGQUIT

EXPOSE 80
EXPOSE 443

CMD ["/usr/sbin/nginx", "-g", "daemon off;"]

FROM alpine:${ALPINE_VERSION} AS builder

RUN apk add --no-cache \
    build-base \
    python3 \
    fcgi-dev \
    libconfig-dev \
    libconfig-static \
    openssl-dev \
    openssl-libs-static \
    git

# Build only the static library, skipping manpages that require a2x.
RUN git clone --depth 1 https://github.com/rg3/libbcrypt.git /tmp/libbcrypt && \
    cd /tmp/libbcrypt && \
    make libbcrypt.a && \
    mkdir -p /usr/local/include /usr/local/lib && \
    cp bcrypt.h /usr/local/include/ && \
    cp libbcrypt.a /usr/local/lib/ && \
    rm -rf /tmp/libbcrypt

WORKDIR /src
COPY src/ .

RUN python3 templ.py && \
    g++ -Wall -std=c++17 -O2 -o nginx-auth \
    -I/usr/local/include \
    server.cc templates.cc \
    -static \
    -lfcgi++ -lfcgi -lpthread -lconfig -lcrypto \
    -L/usr/local/lib -l:libbcrypt.a

FROM base AS auth

RUN apk add --no-cache spawn-fcgi

RUN mkdir -p /var/run/nginx-auth

COPY --from=builder /src/nginx-auth /usr/bin/nginx-auth
COPY root/ /
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
