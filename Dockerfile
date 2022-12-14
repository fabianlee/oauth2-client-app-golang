# builder image
FROM golang:1.19-alpine3.16 as builder
RUN mkdir /build
ADD *.go /build/
ADD *.mod /build/
WORKDIR /build
RUN \
  go get && \
  CGO_ENABLED=0 GOOS=linux go build

# generate clean, final image for end users
FROM alpine:3.16
COPY --from=builder /build/oauth2-client-app-golang .

# executable
ENTRYPOINT [ "./oauth2-client-app-golang" ]
# arguments that can be overridden
#CMD [ "--debug" ]
