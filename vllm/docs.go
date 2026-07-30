package vllm

// FastAPI mounts Swagger UI at /docs and the schema at /openapi.json by default, and vLLM does
// not disable them. A box that answers /v1/models and /metrics like FastAPI but 404s both of
// these is inconsistent with any real deployment.

const swaggerHTML = `
    <!DOCTYPE html>
    <html>
    <head>
    <link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">
    <title>vLLM API - Swagger UI</title>
    </head>
    <body>
    <div id="swagger-ui">
    </div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <!-- ` + "`SwaggerUIBundle` is now available on the page" + ` -->
    <script>
    const ui = SwaggerUIBundle({
        url: '/openapi.json',
    "dom_id": "#swagger-ui",
"layout": "BaseLayout",
"deepLinking": true,
"showExtensions": true,
"showCommonExtensions": true,
oauth2RedirectUrl: window.location.origin + '/docs/oauth2-redirect',
    presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
    })
    </script>
    </body>
    </html>
    `

// openAPISchema returns a structurally faithful, abbreviated FastAPI schema for the routes this
// honeypot serves. Endpoint list and shapes match; the component schemas are trimmed.
func openAPISchema() map[string]any {
	post := func(id, summary string) map[string]any {
		return map[string]any{
			"post": map[string]any{
				"summary":     summary,
				"operationId": id,
				"responses": map[string]any{
					"200": map[string]any{
						"description": "Successful Response",
						"content":     map[string]any{"application/json": map[string]any{"schema": map[string]any{}}},
					},
					"422": map[string]any{
						"description": "Validation Error",
						"content": map[string]any{"application/json": map[string]any{
							"schema": map[string]any{"$ref": "#/components/schemas/HTTPValidationError"},
						}},
					},
				},
			},
		}
	}
	get := func(id, summary string) map[string]any {
		return map[string]any{
			"get": map[string]any{
				"summary":     summary,
				"operationId": id,
				"responses": map[string]any{
					"200": map[string]any{
						"description": "Successful Response",
						"content":     map[string]any{"application/json": map[string]any{"schema": map[string]any{}}},
					},
				},
			},
		}
	}
	return map[string]any{
		"openapi": "3.1.0",
		"info":    map[string]any{"title": "vLLM API", "version": vllmVersion},
		// The path set has to be the router's path set: FastAPI generates this from the same
		// route table it serves, so a documented endpoint that 404s (or vice versa) is a
		// contradiction a scanner gets for free. /ping is absent because vLLM 0.6.3 has no such
		// route — it arrives in 0.7.0. See routes().
		"paths": map[string]any{
			"/health":              get("health_health_get", "Health"),
			"/version":             get("show_version_version_get", "Show Version"),
			"/tokenize":            post("tokenize_tokenize_post", "Tokenize"),
			"/detokenize":          post("detokenize_detokenize_post", "Detokenize"),
			"/v1/models":           get("show_available_models_v1_models_get", "Show Available Models"),
			"/v1/chat/completions": post("create_chat_completion_v1_chat_completions_post", "Create Chat Completion"),
			"/v1/completions":      post("create_completion_v1_completions_post", "Create Completion"),
			"/v1/embeddings":       post("create_embedding_v1_embeddings_post", "Create Embedding"),
		},
		"components": map[string]any{
			"schemas": map[string]any{
				"HTTPValidationError": map[string]any{
					"properties": map[string]any{
						"detail": map[string]any{
							"items": map[string]any{"$ref": "#/components/schemas/ValidationError"},
							"type":  "array", "title": "Detail",
						},
					},
					"type": "object", "title": "HTTPValidationError",
				},
				"ValidationError": map[string]any{
					"properties": map[string]any{
						"loc":  map[string]any{"items": map[string]any{}, "type": "array", "title": "Location"},
						"msg":  map[string]any{"type": "string", "title": "Message"},
						"type": map[string]any{"type": "string", "title": "Error Type"},
					},
					"type": "object", "required": []string{"loc", "msg", "type"}, "title": "ValidationError",
				},
			},
		},
	}
}
