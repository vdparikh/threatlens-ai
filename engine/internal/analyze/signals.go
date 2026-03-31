package analyze

import "strings"

// SecuritySignal is a deterministic pattern hit from static source scanning.
type SecuritySignal struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
}

func detectSecuritySignals(relPath string, src []byte, routes []RouteEntry) []SecuritySignal {
	s := string(src)
	var out []SecuritySignal
	add := func(id, sev, summary string) {
		out = append(out, SecuritySignal{
			ID:       id,
			Path:     relPath,
			Severity: sev,
			Summary:  summary,
		})
	}

	out = append(out, detectGoASTSignals(relPath, src, routes)...)

	if strings.Contains(s, `md.Get("user")`) || strings.Contains(s, `md.Get("x-user")`) {
		add("grpc-metadata-identity-fallback", "MEDIUM",
			"gRPC identity can be sourced from request metadata headers (user/x-user) when mTLS cert identity is absent.")
	}
	if strings.Contains(s, "reflection.Register(") {
		add("grpc-reflection-enabled", "LOW",
			"gRPC server reflection is enabled; consider disabling in production or restricting network access.")
	}
	if strings.Contains(s, `getEnv("HSM_PIN"`) && strings.Contains(s, `"1234"`) {
		add("default-hsm-pin", "HIGH",
			"Default HSM PIN is present in bootstrap config; require secret-manager sourced value in non-dev environments.")
	}
	if strings.Contains(s, `getEnv("HSMAAS_DB_DSN"`) && strings.Contains(s, "password=") {
		add("default-db-dsn-with-password", "MEDIUM",
			"Default DB DSN contains inline credentials; avoid embedded passwords and enforce secret injection.")
	}
	if strings.Contains(s, `if cert == "" || key == ""`) && strings.Contains(s, "return nil") {
		add("tls-optional-config", "MEDIUM",
			"TLS can be disabled when cert/key env vars are absent; enforce TLS/mTLS in production deployment profiles.")
	}
	return dedupeSignalsByIDPath(out)
}
