FROM golang:alpine

LABEL maintainer "Ilya Glotov <ilya@ilyaglotov.com>"

ENV GO111MODULE=on

COPY . /go/src/github.com/ilyaglow/badcapt

RUN apk --update --no-cache add libpcap-dev \
                                git \
                                build-base \
  && cd /go/src/github.com/ilyaglow/badcapt \
  && go mod download \
  && go build -ldflags="-s -w" -a -installsuffix static -o /badcapt cmd/badcapt/badcapt.go

FROM alpine:latest
COPY --from=0 /badcapt /badcapt

RUN apk --update --no-cache add libpcap \
                                libcap \
  && setcap cap_net_raw+eip /badcapt \
  && adduser -D badcapt

USER badcapt
ENTRYPOINT ["/badcapt", "-i", "eth0", "-d"]
