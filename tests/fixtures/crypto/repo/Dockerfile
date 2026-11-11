FROM registry.example.com/ubi9/go-toolset:1.24 AS builder
ARG GOEXPERIMENT=strictfipsruntime
ENV CGO_ENABLED=1
WORKDIR /opt/app-root/src
COPY . .
RUN go build -tags strictfipsruntime -o /tmp/manager ./cmd

FROM registry.example.com/ubi9/ubi-minimal:latest
RUN microdnf install -y openssl-libs && microdnf clean all
LABEL com.example.fips="true"
COPY --from=builder /tmp/manager /manager
ENTRYPOINT ["/manager"]
