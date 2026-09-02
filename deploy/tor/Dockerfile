# Tor from Alpine's signed package index rather than a stranger's prebuilt image: the
# whole point of this service is that you can say where every byte came from.
FROM alpine:3.21
RUN apk add --no-cache tor
USER tor
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
