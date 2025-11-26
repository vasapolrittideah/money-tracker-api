# api gateway

The API Gateway serves as the single entry point for all client requests in the money-tracker-api microservices architecture. It handles request routing, authentication, rate limiting, and provides a unified HTTP REST API interface while communicating with backend services via gRPC.

## Architecture

The API Gateway has the following structure:

```text
services/api-gateway/
├── cmd/                   # Application entry points
│   └── main.go            # Main application bootstrapper
├── internal/              # Private application code
│   ├── config/            # Application configuration
│   ├── handler/           # Request handlers
│   ├── dto/               # Data transfer objects
└── README.md              # Service documentation
```

### Components

**Request Delivery** (`internal/handler`)

- HTTP route definitions and handlers
- Request routing to appropriate backend services
- HTTP-to-gRPC protocol translation
- Response formatting and error handling

**Middleware** (`internal/dto/`)

- API request and response structures
- JSON marshaling/unmarshaling logic
- Data transformation between HTTP and gRPC formats

## Key Features

- **Unified API Interface**: Single HTTP REST endpoint for all client interactions
- **Service Discovery**: Automatic discovery and load balancing via Consul
- **Protocol Translation**: HTTP to gRPC communication with backend services
- **Authentication**: JWT-based authentication and authorization
- **Rate Limiting**: Configurable rate limiting per client/endpoint
- **Observability**: Structured logging, metrics, and request tracing

### Configuration

The service uses environment variables for configuration. See `internal/config/` for available options.
