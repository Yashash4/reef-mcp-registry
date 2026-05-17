package inspector

import "testing"

func TestDetectMCPBind(t *testing.T) {
	cases := []struct {
		name          string
		text          string
		wantName      string
		wantVer       string
		wantTransport string
		wantFound     bool
	}{
		{
			name:          "bind_mcp call full",
			text:          `bind_mcp("io.github.modelcontextprotocol/server-filesystem", "0.6.3", "stdio")`,
			wantName:      "io.github.modelcontextprotocol/server-filesystem",
			wantVer:       "0.6.3",
			wantTransport: "stdio",
			wantFound:     true,
		},
		{
			name:      "bind_mcp call name only",
			text:      `bind_mcp("victim-mcp-server")`,
			wantName:  "victim-mcp-server",
			wantFound: true,
		},
		{
			name:      "bind_mcp call name and version",
			text:      `bind_mcp("com.example/weather-mcp", "1.2.3")`,
			wantName:  "com.example/weather-mcp",
			wantVer:   "1.2.3",
			wantFound: true,
		},
		{
			name:      "mcp uri with version",
			text:      `try mcp://com.example/weather-mcp@1.2.3 first`,
			wantName:  "com.example/weather-mcp",
			wantVer:   "1.2.3",
			wantFound: true,
		},
		{
			name:      "mcp uri without version",
			text:      `register mcp://org.langchain.mcp.weather`,
			wantName:  "org.langchain.mcp.weather",
			wantFound: true,
		},
		{
			name:      "natural language bind",
			text:      `please bind to MCP server com.example/weather-mcp and summarise`,
			wantName:  "com.example/weather-mcp",
			wantFound: true,
		},
		{
			name:      "natural language bind with victim alias",
			text:      `connect victim-mcp-server to my agent fleet`,
			wantName:  "victim-mcp-server",
			wantFound: true,
		},
		{
			name:      "benign prompt detects nothing",
			text:      `please summarise my inbox`,
			wantFound: false,
		},
		{
			name:      "empty text returns nothing",
			text:      ``,
			wantFound: false,
		},
		{
			name:      "case insensitive function call",
			text:      `Bind_MCP("com.example/weather-mcp")`,
			wantName:  "com.example/weather-mcp",
			wantFound: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			name, ver, tr, ok := DetectMCPBind(c.text)
			if ok != c.wantFound {
				t.Fatalf("found = %v, want %v (name=%q)", ok, c.wantFound, name)
			}
			if !c.wantFound {
				return
			}
			if name != c.wantName {
				t.Errorf("name = %q, want %q", name, c.wantName)
			}
			if c.wantVer != "" && ver != c.wantVer {
				t.Errorf("version = %q, want %q", ver, c.wantVer)
			}
			if c.wantTransport != "" && tr != c.wantTransport {
				t.Errorf("transport = %q, want %q", tr, c.wantTransport)
			}
		})
	}
}

func TestInspector_PopulatesMCPBindFields(t *testing.T) {
	ins := New()
	meta := ins.Inspect(`bind_mcp("com.example/weather-mcp", "1.2.3", "http")`)
	if meta.MCPBindTarget != "com.example/weather-mcp" {
		t.Errorf("MCPBindTarget = %q", meta.MCPBindTarget)
	}
	if meta.MCPBindVersion != "1.2.3" {
		t.Errorf("MCPBindVersion = %q", meta.MCPBindVersion)
	}
	if meta.MCPBindTransport != "http" {
		t.Errorf("MCPBindTransport = %q", meta.MCPBindTransport)
	}
}

func TestInspector_BenignPromptLeavesMCPBindEmpty(t *testing.T) {
	ins := New()
	meta := ins.Inspect("Hello, please summarise my inbox.")
	if meta.MCPBindTarget != "" {
		t.Errorf("expected empty MCPBindTarget, got %q", meta.MCPBindTarget)
	}
}
