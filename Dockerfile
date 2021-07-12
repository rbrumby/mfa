FROM golang:1.16.5 as build

RUN mkdir /mfa
COPY *.* /mfa/
ARG CGO_ENABLED=0
ARG GOOS=linux
ARG GOARCH=amd64
RUN cd /mfa && go build -o ./mfa mfa.go

FROM scratch
ENV HOME=/
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /mfa/mfa /mfa
ENTRYPOINT ["/mfa"]