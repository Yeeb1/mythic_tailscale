FROM golang:1.24 AS gobuilder

WORKDIR /build
COPY tailscale/c2_code/ ./
RUN go mod download
# Build the server binary during docker build
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /opt/server .

FROM itsafeaturemythic/mythic_python_dotnet:latest

WORKDIR /Mythic/
COPY [".", "."]

# Include Go toolchain for rebuilds if source changes
COPY --from=gobuilder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/opt/go"
ENV GOMODCACHE="/opt/go/pkg/mod"
ENV GOCACHE="/opt/go-cache"

# Copy pre-built binary and cached modules outside /Mythic/ (survives volume mount)
COPY --from=gobuilder /opt/server /opt/server
COPY --from=gobuilder /go/pkg/mod /opt/go/pkg/mod

# Warm the build cache from the runtime path so rebuilds are fast
RUN cd /Mythic/tailscale/c2_code && \
    CGO_ENABLED=0 go build -ldflags "-s -w" -o /dev/null .

RUN chmod +x /Mythic/tailscale/c2_code/start_server.py && \
    pip install -r requirements.txt

CMD ["python3", "main.py"]
