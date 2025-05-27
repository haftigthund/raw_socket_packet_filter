FROM alpine:latest

RUN apk add --no-cache build-base iputils-ping tcpdump libpcap-dev

WORKDIR /app

COPY packet_filter.c .

RUN gcc packet_filter.c -o packet_filter

CMD [ "sh", "-c", "echo 0 > /proc/sys/net/ipv4/ip_forward && ./packet_filter" ]