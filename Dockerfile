ARG ALPINE_VERSION=3.22

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

# Build libbcrypt as static library (no musl symbol conflicts)
RUN git clone --depth 1 https://github.com/rg3/libbcrypt.git /tmp/libbcrypt && \
    cd /tmp/libbcrypt && \
    make && \
    mkdir -p /usr/local/include /usr/local/lib && \
    cp bcrypt.h /usr/local/include/ && \
    cp bcrypt.a /usr/local/lib/ && \
    rm -rf /tmp/libbcrypt

WORKDIR /src
COPY src/ .

RUN python3 templ.py && \
    g++ -Wall -std=c++17 -O2 -o nginx-auth \
    -I/usr/local/include \
    server.cc templates.cc \
    -static \
    -lfcgi++ -lfcgi -lpthread -lconfig -lcrypto \
    -L/usr/local/lib -l:bcrypt.a

FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache \
    tzdata \
    nginx \
    spawn-fcgi

RUN mkdir -p /var/run/nginx-auth

COPY --from=builder /src/nginx-auth /usr/bin/nginx-auth
COPY root/ /
RUN chmod +x /docker-entrypoint.sh

STOPSIGNAL SIGQUIT

EXPOSE 80
EXPOSE 443

ENTRYPOINT ["/docker-entrypoint.sh"]
