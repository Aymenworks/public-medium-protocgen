# Proto-First Authorization System

A protobuf plugin that automatically generates authorization maps from proto file annotations, enabling seamless role-based permission management for gRPC/HTTP APIs.

## What is this project?

This project demonstrates how to build a **proto-first authorization system** that:

- 📝 **Defines permissions directly in proto files** using custom options
- 🔧 **Automatically generates Go code** with endpoint-to-permissions mappings
- 🚀 **Eliminates manual permission management** and reduces human error
- 🔒 **Provides ready-to-use authorization helpers** for your application

### Example

Instead of manually managing permissions in your codebase, you define them directly in your proto files:

```proto
service TestService {
  rpc TestNoPermissions(TestRequest) returns (TestResponse) {
    option (google.api.http) = {
      post: "/v1/test/{foo_id}"
      body: "*"
    };
    option (proto.v1.authz) = {no_auth_required: true};
  }

  rpc TestWithPermissions(TestRequest) returns (TestResponse) {
    option (google.api.http) = {
      post: "/v1/test2/{foo_id}"
      body: "*"
    };
    option (proto.v1.authz) = {
      permissions: ["read:all"]
    };
  }
}
```

And the plugin automatically generates:

```go
var generatedAuthzMap = map[string]AuthzRule{
    "/v1/test/{foo_id}|POST": {
        Permissions:    []string{},
        NoAuthRequired: true,
    },
    "/v1/test2/{foo_id}|POST": {
        Permissions:    []string{"read:all"},
        NoAuthRequired: false,
    },
}
```

## Prerequisites

- [Buf CLI](https://docs.buf.build/installation) (for protocol buffer management)

## Setup and Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/aymenworks/public-medium-protocgen
   cd public-medium-protocgen
   ```

2. **Install dependencies:**
   ```bash
   go mod download
   ```

3. **Install required tools:**
   ```bash
   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
   go install github.com/bufbuild/buf/cmd/buf@latest
   ```

## Usage

### Generate Code

Run the buf generate command to generate both standard Go proto code and authorization mappings:

```bash
go tool buf generate
```

This command will:
- Parse your proto files
- Extract authorization annotations
- Generate Go structs and gRPC service definitions
- Create authorization mapping code in the `./gen` directory

### Generated Files

After running the generation, you'll find:
- `./gen/proto/v1/` - Standard generated Go protobuf code
- `./gen/proto/v1/authz.pb.go` - Authorization mappings and helper functions

### Using in Your Application

Import and use the generated authorization code:

```go
import "your-module/gen/proto/v1"

// Check if user has permissions for an endpoint
if hasPermissions(generatedAuthzMap, reqPath, reqMethod, userPermissions) {
    // User authorized
} else {
    // Access denied
}
```

## Configuration

The generation behavior is configured in `buf.gen.yaml`:

```yaml
version: v2
clean: true
managed:
  enabled: true
plugins:
  - local: [go, tool, google.golang.org/protobuf/cmd/protoc-gen-go]
    out: ./gen
    opt:
      - paths=import
  - local: [go, run, ./protoc-gen-go-authz]  # Custom authorization plugin
    out: ./gen
    opt:
      - paths=source_relative
    strategy: all
```


## Related Article

This project is featured in the blog post: **TODO** which walks through the development process and lessons learned.
