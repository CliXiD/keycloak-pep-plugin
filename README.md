# Keycloak Policy Enforcer Plugin for Traefik

A Traefik middleware plugin that implements Keycloak Policy Enforcement Point (PEP) functionality, providing fine-grained authorization control at the API gateway level.

## Features

- 🔐 JWT token validation with Keycloak
- 🛡️ Policy-based access control (PBAC)
- 🎯 Path-based resource protection
- 🔍 Scope and role validation
- ⚡ Configurable enforcement modes
- 💾 Built-in caching for performance
- 📊 Comprehensive logging and metrics

## Quick Start

### 1. Installation

Add the plugin to your Traefik configuration:

```yaml
# docker-compose.yml
version: '3.7'
services:
  traefik:
    image: traefik:v3.0
    command:
      - "--experimental.plugins.keycloak-pep.modulename=github.com/CliXiD/keycloak-pep-plugin"
      - "--experimental.plugins.keycloak-pep.version=v1.0.0"
```

### 2. Configuration

```yaml
# traefik.yml
http:
  middlewares:
    keycloak-pep:
      plugin:
        keycloak-pep:
          keycloak:
            server_url: "https://keycloak.example.com"
            realm: "my-realm"
            client_id: "my-api-gateway"
            client_secret: "your-client-secret"
          enforcement_mode: "ENFORCING"
          paths:
            - path: "/api/admin/*"
              methods: ["GET", "POST", "PUT", "DELETE"]
              scopes: ["admin:read", "admin:write"]
              roles: ["admin"]
            - path: "/api/user/*"
              methods: ["GET"]
              scopes: ["user:read"]

  routers:
    api:
      rule: "PathPrefix(`/api`)"
      service: api-service
      middlewares:
        - keycloak-pep
```

### 3. Test the Setup

```bash
# Request without token (should be denied)
curl -X GET http://localhost/api/admin/users

# Request with valid token
curl -X GET http://localhost/api/admin/users \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Configuration Reference

### Core Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `enforcement_mode` | string | No | Policy enforcement mode: `ENFORCING`, `PERMISSIVE`, `DISABLED` |
| `timeout` | duration | No | HTTP client timeout (default: 30s) |

### Keycloak Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `server_url` | string | Yes | Keycloak server base URL |
| `realm` | string | Yes | Keycloak realm name |
| `client_id` | string | Yes | Client ID for the application |
| `client_secret` | string | No | Client secret (for confidential clients) |
| `use_resource_name` | bool | No | Use resource name matching |
| `lazy_load_paths` | bool | No | Enable lazy loading of resource paths |

### Path Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | Path pattern to protect (supports wildcards) |
| `methods` | []string | No | HTTP methods to protect |
| `scopes` | []string | No | Required OAuth2 scopes |
| `roles` | []string | No | Required user roles |
| `enforcement_mode` | string | No | Override global enforcement mode |
| `resource_name` | string | No | Keycloak resource name |
| `claims_validation` | map | No | Custom JWT claims validation |

### Cache Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `enabled` | bool | No | Enable caching (default: true) |
| `token_ttl` | duration | No | Token cache TTL (default: 5m) |
| `policy_ttl` | duration | No | Policy cache TTL (default: 10m) |
| `max_size` | int | No | Maximum cache entries (default: 1000) |

## Enforcement Modes

### ENFORCING (Default)
- Strict policy enforcement
- Denies access on policy violations
- Returns HTTP 403 for unauthorized requests
- Recommended for production environments

### PERMISSIVE
- Logs policy violations but allows access
- Useful for testing and gradual rollout
- Returns HTTP 200 but logs security events

### DISABLED
- No policy enforcement
- All requests are allowed through
- Useful for maintenance or emergency access

## Path Matching

The plugin supports flexible path matching patterns:

```yaml
paths:
  # Exact match
  - path: "/api/users"

  # Wildcard match (single segment)
  - path: "/api/users/*"

  # Recursive wildcard match
  - path: "/api/admin/**"

  # Pattern matching
  - path: "/api/files/*.pdf"
```

## Token Validation

The plugin validates JWT tokens through Keycloak's token introspection endpoint:

1. **Token Extraction**: Extracts JWT from `Authorization: Bearer <token>` header
2. **Introspection**: Validates token with Keycloak
3. **Claims Extraction**: Extracts scopes, roles, and custom claims
4. **Policy Evaluation**: Checks token against configured policies

## Development

### Prerequisites

- Go 1.21+
- Docker & Docker Compose
- Access to a Keycloak instance

### Building

```bash
# Install dependencies
go mod tidy

# Build the plugin
go build -buildmode=plugin .

# Run tests
go test ./...

# Run with coverage
go test -cover ./...
```

### Testing

```bash
# Start test environment
docker-compose up -d keycloak

# Run unit tests
go test -v ./internal/...

# Run integration tests
go test -v ./tests/integration/...

# Clean up
docker-compose down
```

### Local Development

1. Start Keycloak:
```bash
docker-compose up keycloak
```

2. Configure test realm and client in Keycloak

3. Update configuration in `examples/traefik.yml`

4. Test with Traefik:
```bash
docker-compose -f docker-compose.test.yml up --build
```

## Examples

Check the `examples/` directory for:
- Complete Docker Compose setup
- Traefik configuration examples
- Keycloak realm configuration
- Test scripts and sample requests

## Troubleshooting

### Common Issues

**Token validation fails**
- Verify Keycloak server URL and realm
- Check client credentials
- Ensure token is not expired

**Path not matching**
- Check path pattern syntax
- Verify HTTP method configuration
- Review Traefik routing rules

**Performance issues**
- Enable caching
- Tune cache TTL values
- Check Keycloak server performance

### Debug Logging

Enable debug logging in Traefik:

```yaml
log:
  level: DEBUG
  filePath: "/var/log/traefik.log"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Create a pull request

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Support

- 📖 [Documentation](./docs/)
- 🐛 [Issue Tracker](https://github.com/CliXiD/keycloak-pep-plugin/issues)
- 💬 [Discussions](https://github.com/CliXiD/keycloak-pep-plugin/discussions)

## Acknowledgments

- Based on [Keycloak Policy Enforcer](https://github.com/keycloak/keycloak-client/tree/main/policy-enforcer)
- Built for [Traefik](https://traefik.io/) proxy
- Inspired by [Keycloak Authorization Services](https://www.keycloak.org/docs/latest/authorization_services/)