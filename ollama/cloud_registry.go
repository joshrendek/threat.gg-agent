package ollama

// September 2026 cloud catalog refresh (threat_gg-ldey). These are tiny remote
// stubs, not local weights. Names, digests, sizes and metadata were captured from
// registry.ollama.ai manifests/configs and ollama.com/api/show on 2026-09-06.
// Preserve the existing models because active clients still select those names.
var registryCloudModels = []CatalogModel{
	{
		Name: "minimax-m3:cloud", Model: "minimax-m3:cloud",
		RemoteModel: "minimax-m3", RemoteHost: cloudHost,
		Size: 301, Digest: "8cd948b96f47afd232cef7d49faf65791d22bd9dbbef74add3b9355d9d75f765",
		Details:      Details{ParameterSize: "0", QuantizationLevel: "", ContextLength: 524288, EmbeddingLength: 0},
		Capabilities: []string{"completion", "tools", "thinking", "vision"},
	},
	{
		Name: "kimi-k2.7-code:cloud", Model: "kimi-k2.7-code:cloud",
		RemoteModel: "kimi-k2.7-code", RemoteHost: cloudHost,
		Size: 320, Digest: "e30d96cd393660995bd710d190440b53388b753086b9c2cf8fd098d16a567def",
		Details:      Details{ParameterSize: "1.04T", QuantizationLevel: "INT4", ContextLength: 262144, EmbeddingLength: 2048},
		Capabilities: []string{"vision", "thinking", "completion", "tools"},
	},
	{
		Name: "deepseek-v4-flash:cloud", Model: "deepseek-v4-flash:cloud",
		RemoteModel: "deepseek-v4-flash:0731", RemoteHost: cloudHost,
		Size: 326, Digest: "d3f1c87447216481a8001f48c517a51e13bfb141853a8df5e52f81bf765dabc3",
		Details:      Details{ParameterSize: "304B", QuantizationLevel: "FP8", ContextLength: 1048576, EmbeddingLength: 4096},
		Capabilities: []string{"completion", "tools", "thinking"},
	},
	{
		Name: "glm-5.3:cloud", Model: "glm-5.3:cloud",
		RemoteModel: "glm-5.3", RemoteHost: cloudHost,
		Size: 293, Digest: "8477dab3e25bb0f93c468af220186f55394262ee5e9f39262af4b60b54a8c4ba",
		Details:      Details{ParameterSize: "753B", QuantizationLevel: "FP8", ContextLength: 1048576, EmbeddingLength: 0},
		Capabilities: []string{"completion", "thinking", "tools"},
	},
	{
		Name: "gemma4:31b-cloud", Model: "gemma4:31b-cloud",
		RemoteModel: "gemma4:31b", RemoteHost: cloudHost,
		Size: 312, Digest: "ef09f235533c96cd75e8deed88c628335cb69e2b3ce96275d0d7a67fe9887aba",
		Details:      Details{ParameterSize: "32.7B", QuantizationLevel: "BF16", ContextLength: 262144, EmbeddingLength: 5376},
		Capabilities: []string{"completion", "thinking", "tools", "vision"},
	},
	{
		Name: "glm-5.1:cloud", Model: "glm-5.1:cloud",
		RemoteModel: "glm-5.1", RemoteHost: cloudHost,
		Size: 295, Digest: "7aea7667808a4aed9488836bd4b2800a57287faf6273f436c8b5fbbe65a441c1",
		Details:      Details{ParameterSize: "756B", QuantizationLevel: "FP8", ContextLength: 202752, EmbeddingLength: 6144},
		Capabilities: []string{"thinking", "completion", "tools"},
	},
	{
		Name: "glm-5.3-flash:cloud", Model: "glm-5.3-flash:cloud",
		RemoteModel: "glm-5.3-flash", RemoteHost: cloudHost,
		Size: 317, Digest: "3e780905abc0e7240dd1489935ec1e3c7fcf1854a6f4e7f8688f9bb0bdacb1a5",
		Details:      Details{ParameterSize: "321B", QuantizationLevel: "FP8", ContextLength: 1048576, EmbeddingLength: 4096},
		Capabilities: []string{"completion", "thinking", "tools", "vision"},
	},
	{
		Name: "deepseek-v4-flash:0731-cloud", Model: "deepseek-v4-flash:0731-cloud",
		RemoteModel: "deepseek-v4-flash:0731", RemoteHost: cloudHost,
		Size: 326, Digest: "d3f1c87447216481a8001f48c517a51e13bfb141853a8df5e52f81bf765dabc3",
		Details:      Details{ParameterSize: "304B", QuantizationLevel: "FP8", ContextLength: 1048576, EmbeddingLength: 4096},
		Capabilities: []string{"completion", "tools", "thinking"},
	},
}
