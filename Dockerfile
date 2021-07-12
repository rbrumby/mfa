FROM golang:1.16.5 as build

COPY ./ /mfa/
ARG CGO_ENABLED=0
ARG GOOS=linux
ARG GOARCH=amd64
RUN cd /mfa/cmd && go build -o ./mfa

FROM scratch
ENV HOME=/
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /mfa/cmd/mfa /mfa
ENTRYPOINT ["/mfa"]