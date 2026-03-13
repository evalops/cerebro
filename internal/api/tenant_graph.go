package api

import (
	"context"
	"strings"

	"github.com/evalops/cerebro/internal/graph"
)

func (s *Server) tenantScopedGraph(ctx context.Context, g *graph.Graph) *graph.Graph {
	if s == nil || g == nil {
		return nil
	}
	tenantID := strings.TrimSpace(GetTenantID(ctx))
	return g.SubgraphForTenant(tenantID)
}

func (s *Server) currentTenantSecurityGraph(ctx context.Context) *graph.Graph {
	if s == nil || s.app == nil {
		return nil
	}
	return s.tenantScopedGraph(ctx, s.app.CurrentSecurityGraph())
}

func (s *Server) currentTenantRiskEngine(ctx context.Context) *graph.RiskEngine {
	if s == nil || s.app == nil {
		return nil
	}
	if strings.TrimSpace(GetTenantID(ctx)) == "" {
		return s.graphRiskEngine()
	}
	g := s.currentTenantSecurityGraph(ctx)
	if g == nil {
		return nil
	}
	engine := graph.NewRiskEngine(g)
	if s.app.Config != nil {
		engine.SetCrossTenantPrivacyConfig(graph.CrossTenantPrivacyConfig{
			MinTenantCount:    s.app.Config.GraphCrossTenantMinTenants,
			MinPatternSupport: s.app.Config.GraphCrossTenantMinSupport,
		})
	}
	return engine
}
