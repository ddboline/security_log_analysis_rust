FROM rust:alpine3.14 as buildstage

RUN apk add musl-dev && mkdir -p /build/security_log_analysis_rust

ADD Cargo.toml /build/security_log_analysis_rust/
COPY src /build/security_log_analysis_rust/src
COPY migrations /build/security_log_analysis_rust/migrations
COPY templates /build/security_log_analysis_rust/templates

RUN mkdir -p /security_log_analysis_rust && \
    cd /build/security_log_analysis_rust && \
    cargo install --path=. --root=/security_log_analysis_rust

FROM alpine:3.14

COPY --from=buildstage /security_log_analysis_rust/bin/* /usr/bin/

STOPSIGNAL SIGTERM

CMD ["/usr/bin/notification-app-api"]
