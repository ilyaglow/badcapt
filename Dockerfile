FROM golang:alpine

LABEL maintainer "Ilya Milov <contact@ilya.app>"

ENV GO111MODULE=on

RUN apk --update --no-cache add libpcap-dev \
                                git \
                                build-base

COPY . /go/src/github.com/ilyaglow/badcapt

RUN cd /go/src/github.com/ilyaglow/badcapt \
  && go mod download \
  && go build -ldflags="-s -w" -a -installsuffix static -o /badcapt cmd/badcapt/badcapt.go

FROM scratch
ADD https://raw.githubusercontent.com/nmap/nmap/master/nmap-services /nmap-services

FROM alpine:latest
RUN apk --update --no-cache add libpcap \
                                libcap \
  && adduser -D badcapt

COPY --from=0 /badcapt /badcapt
COPY --from=1 /nmap-services /nmap-services

RUN setcap cap_net_raw+eip /badcapt \
  && chown badcapt:badcapt /nmap-services

USER badcapt
ENTRYPOINT ["/badcapt"]
CMD ["-h"]
