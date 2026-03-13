FROM golang:1.24 AS gobuilder

WORKDIR /build
# Copy full agent source for dependency download
COPY cercopes/agent_code/ ./
RUN go mod download

FROM itsafeaturemythic/mythic_python_dotnet:latest

WORKDIR /Mythic/
COPY [".", "."]

# Install Go for build-time compilation
COPY --from=gobuilder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/opt/go"
ENV GOMODCACHE="/opt/go/pkg/mod"
ENV GOCACHE="/opt/go-cache"

# Copy pre-cached Go module dependencies
COPY --from=gobuilder /go/pkg/mod /opt/go/pkg/mod

# Warm-up build from the exact runtime path to populate build cache
# This ensures subsequent builds with different ldflags only take seconds
RUN cd /Mythic/cercopes/agent_code && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o /dev/null . && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o /dev/null . && \
    CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o /dev/null . && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o /dev/null . && \
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o /dev/null .

RUN pip install -r requirements.txt

CMD ["python3", "main.py"]
