ARG ALPINE_VERSION=3.21
ARG GO_VERSION=1.24.2

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build

WORKDIR /src

COPY . .

RUN go build -o ./certwarden-client ./pkg/main

FROM alpine:${ALPINE_VERSION}

WORKDIR /app

RUN apk add --no-cache tzdata

COPY --from=build /src/certwarden-client .
COPY --from=build /src/README.md .
COPY --from=build /src/CHANGELOG.md .
COPY --from=build /src/LICENSE.md .

EXPOSE 5055/tcp

CMD /app/certwarden-client
