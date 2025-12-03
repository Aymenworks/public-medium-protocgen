package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// protoAuthzParser handles parsing of authz options from proto files.
type protoAuthzParser struct {
	authzExtensionNumber protoreflect.FieldNumber
}

// newProtoAuthzParser creates a new parser.
func newProtoAuthzParser() *protoAuthzParser {
	return &protoAuthzParser{
		authzExtensionNumber: 50001, // proto.v1.authz extension number from option.proto
	}
}

// parseFile extracts all authz rules from a proto file.
func (p *protoAuthzParser) parseFile(file *protogen.File) []authzRule {
	rules := make([]authzRule, 0, len(file.Services))

	for _, service := range file.Services {
		log.Printf("service: %s\n\n]]", service.Desc.Name())
		serviceRules := p.parseService(service)
		rules = append(rules, serviceRules...)
	}

	return rules
}

// parseService extracts authz rules from all methods in a service.
func (p *protoAuthzParser) parseService(service *protogen.Service) []authzRule {
	rules := make([]authzRule, 0, len(service.Methods))

	for _, method := range service.Methods {
		log.Printf("method: %s\n", method.Desc.Name())
		rule, err := p.parseMethod(method)
		if err != nil {
			// Skip methods without authz options - this is normal
			continue
		}
		rules = append(rules, rule)
	}

	return rules
}

// parseMethod extracts authz rule from a single method.
func (p *protoAuthzParser) parseMethod(method *protogen.Method) (authzRule, error) {
	// Extract authz permissions and no_auth_required flag
	permissions, noAuthRequired, err := p.extractAuthzOptions(method)
	log.Printf("permissions: %v, noAuthRequired: %v\n\n", permissions, noAuthRequired)
	if err != nil {
		return authzRule{}, fmt.Errorf("failed to extract authz options: %w", err)
	}

	// Extract HTTP information
	httpPath, httpMethod, err := p.extractHTTPInfo(method)
	log.Printf("httpPath: %s, httpMethod: %s\n", httpPath, httpMethod)
	if err != nil {
		return authzRule{}, fmt.Errorf("failed to extract HTTP info: %w", err)
	}

	return authzRule{
		HTTPPath:       httpPath,
		HTTPMethod:     httpMethod,
		Permissions:    permissions,
		NoAuthRequired: noAuthRequired,
	}, nil
}

// extractAuthzOptions extracts both permissions and no_auth_required from the authz extension.
func (p *protoAuthzParser) extractAuthzOptions(method *protogen.Method) ([]string, bool, error) {
	// Extract options by examining the proto file directly
	return p.extractFromProtoSource(method)
}

// extractFromProtoSource extracts permissions and no_auth_required by examining the proto source.
func (p *protoAuthzParser) extractFromProtoSource(method *protogen.Method) ([]string, bool, error) {
	// Get the proto file path and read it
	protoPath := method.Desc.ParentFile().Path()

	// Parse the proto file content to find authz options
	methodName := string(method.Desc.Name())

	// Extract from the proto file content for any service/method
	return p.extractAuthzFromProtoFile(protoPath, methodName)
}

// extractAuthzFromProtoFile extracts permissions and no_auth_required by parsing proto file for any service/method.
func (p *protoAuthzParser) extractAuthzFromProtoFile(protoPath, methodName string) ([]string, bool, error) {
	log.Printf("extractAuthzFromProtoFile: %s, %s\n", protoPath, methodName)
	// Read the proto file content
	content, err := os.ReadFile(protoPath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read proto file: %w", err)
	}

	// Find the method by looking for rpc methodName and then finding its complete body
	rpcPattern := fmt.Sprintf(`rpc\s+%s\s*\([^)]*\)\s*returns\s*\([^)]*\)\s*\{`, regexp.QuoteMeta(methodName))
	rpcRegex := regexp.MustCompile(rpcPattern)
	rpcMatch := rpcRegex.FindStringIndex(string(content))

	if rpcMatch == nil {
		return nil, false, fmt.Errorf("method %s not found in proto file", methodName)
	}

	// Find the opening brace and extract content until the matching closing brace
	openBrace := rpcMatch[1] - 1 // Position of the opening brace
	braceCount := 1
	pos := openBrace + 1

	for pos < len(content) && braceCount > 0 {
		switch content[pos] {
		case '{':
			braceCount++
		case '}':
			braceCount--
		}
		pos++
	}

	if braceCount != 0 {
		return nil, false, fmt.Errorf("unmatched braces in method %s", methodName)
	}

	methodBody := string(content[openBrace+1 : pos-1])

	// Look for authz block in the method body
	// Use a more robust approach to extract nested blocks with comments
	authzStartRegex := regexp.MustCompile(`option\s*\(\s*proto\.v1\.authz\s*\)\s*=\s*\{`)
	authzStartMatch := authzStartRegex.FindStringIndex(methodBody)

	if authzStartMatch == nil {
		return nil, false, fmt.Errorf("authz options not found for method %s", methodName)
	}

	// Extract the authz block content by counting braces
	authzStartPos := authzStartMatch[1] // Position after the opening brace
	authzBraceCount := 1
	authzCurPos := authzStartPos

	for authzCurPos < len(methodBody) && authzBraceCount > 0 {
		switch methodBody[authzCurPos] {
		case '{':
			authzBraceCount++
		case '}':
			authzBraceCount--
		}
		authzCurPos++
	}

	if authzBraceCount != 0 {
		return nil, false, fmt.Errorf("unmatched braces in authz block for method %s", methodName)
	}

	authzBody := methodBody[authzStartPos : authzCurPos-1]

	// Remove all commented lines from authzBody
	// Remove single-line comments (// ...)
	singleLineCommentRegex := regexp.MustCompile(`(?m)^\s*//.*$`)
	authzBody = singleLineCommentRegex.ReplaceAllString(authzBody, "")

	// Remove multi-line comments (/* ... */)
	multiLineCommentRegex := regexp.MustCompile(`/\*[\s\S]*?\*/`)
	authzBody = multiLineCommentRegex.ReplaceAllString(authzBody, "")

	// Extract permissions from non-commented content
	var permissions []string
	permissionsRegex := regexp.MustCompile(`permissions\s*:\s*\[(.*?)\]`)
	permMatches := permissionsRegex.FindStringSubmatch(authzBody)
	if len(permMatches) >= 2 {
		permissions, err = p.parsePermissionsString(permMatches[1])
		if err != nil {
			return nil, false, fmt.Errorf("failed to parse permissions: %w", err)
		}
	}

	// Extract no_auth_required
	noAuthRequired := false
	noAuthRegex := regexp.MustCompile(`no_auth_required\s*:\s*(true|false)`)
	noAuthMatches := noAuthRegex.FindStringSubmatch(authzBody)
	if len(noAuthMatches) >= 2 {
		noAuthRequired = noAuthMatches[1] == "true"
	}

	log.Printf("permissions: %v, noAuthRequired: %v\n", permissions, noAuthRequired)
	return permissions, noAuthRequired, nil
}

// parsePermissionsString parses permissions from a string like "aaaa", "bbbb", "cccc".
func (p *protoAuthzParser) parsePermissionsString(permissionsStr string) ([]string, error) {
	log.Printf("parsePermissionsString: %s\n", permissionsStr)
	// Remove whitespace and split by commas
	permissionsStr = strings.TrimSpace(permissionsStr)
	if permissionsStr == "" {
		return []string{}, nil
	}

	// Split by comma and clean each permission
	rawPermissions := strings.Split(permissionsStr, ",")
	permissions := make([]string, 0, len(rawPermissions))

	for _, perm := range rawPermissions {
		// Remove whitespace and quotes
		perm = strings.TrimSpace(perm)
		perm = strings.Trim(perm, `"`)
		perm = strings.Trim(perm, `'`)
		if perm != "" {
			permissions = append(permissions, perm)
		}
	}

	log.Printf("permissions: %v\n", permissions)
	return permissions, nil
}

// extractHTTPInfo extracts HTTP path and method from google.api.http annotation.
func (p *protoAuthzParser) extractHTTPInfo(method *protogen.Method) (string, string, error) {

	// Try to get HTTP info from the method options
	methodOpts := method.Desc.Options().(*descriptorpb.MethodOptions)
	log.Printf("methodOpts: %#v\n", methodOpts)
	// Check if google.api.http extension exists
	if proto.HasExtension(methodOpts, annotations.E_Http) {
		httpRule := proto.GetExtension(methodOpts, annotations.E_Http)
		log.Printf("httpRule: %+v\n", httpRule)
		if httpRule != nil {
			return p.extractHTTPInfoFromRule(httpRule)
		}
	}

	// If no HTTP extension found, return error
	return "", "", fmt.Errorf("no HTTP annotation found")
}

// extractHTTPInfoFromRule extracts path and method from HTTP rule.
func (p *protoAuthzParser) extractHTTPInfoFromRule(httpRule any) (string, string, error) {
	// The HTTP rule should be a message containing HTTP info
	msg, ok := httpRule.(protoreflect.ProtoMessage)
	if !ok {
		return "", "", fmt.Errorf("HTTP rule is not a proto message")
	}
	log.Printf("extractHTTPInfoFromRule: %v\n", msg)

	reflectMsg := msg.ProtoReflect()
	fields := reflectMsg.Descriptor().Fields()

	log.Printf("reflectMsg = %v\n", reflectMsg.Descriptor())
	// Check for different HTTP methods (get, post, put, delete, patch)
	for i := range fields.Len() {
		field := fields.Get(i)
		log.Printf("field: %s\n", field.Name())
		if !reflectMsg.Has(field) {
			continue
		}

		switch field.Name() {
		case "get":
			path := reflectMsg.Get(field).String()
			return path, "GET", nil
		case "post":
			path := reflectMsg.Get(field).String()
			return path, "POST", nil
		case "put":
			path := reflectMsg.Get(field).String()
			return path, "PUT", nil
		case "delete":
			path := reflectMsg.Get(field).String()
			return path, "DELETE", nil
		case "patch":
			path := reflectMsg.Get(field).String()
			return path, "PATCH", nil
		}
	}

	return "", "", fmt.Errorf("no HTTP method found in rule")
}
