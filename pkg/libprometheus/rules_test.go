package libprometheus_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	libprom "github.com/portainer/portainer/pkg/libprometheus"
	pkgmetrics "github.com/portainer/portainer/pkg/metrics"
	prometheusreg "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRuleManager(t *testing.T) {
	reg := prometheusreg.NewRegistry()
	db, err := libprom.NewInMemoryTSDB(reg)
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()

	engine := libprom.NewEngine()

	var notified bool
	mgr := libprom.NewRuleManager(libprom.RuleManagerConfig{
		Engine:     engine,
		Queryable:  db,
		Appendable: db,
		NotifyFunc: func(_ context.Context, _ string, alerts ...*rules.Alert) {
			notified = true
		},
		Context:    context.Background(),
		Registerer: reg,
	})

	require.NotNil(t, mgr)
	_ = notified // used by rule evaluation, not directly testable without running the manager
}

func TestReloadRules(t *testing.T) {
	reg := prometheusreg.NewRegistry()
	db, err := libprom.NewInMemoryTSDB(reg)
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()

	engine := libprom.NewEngine()

	mgr := libprom.NewRuleManager(libprom.RuleManagerConfig{
		Engine:     engine,
		Queryable:  db,
		Appendable: db,
		NotifyFunc: func(_ context.Context, _ string, _ ...*rules.Alert) {},
		Context:    context.Background(),
		Registerer: reg,
	})

	t.Run("empty path clears rules", func(t *testing.T) {
		err := libprom.ReloadRules(mgr, 15*time.Second, "")
		require.NoError(t, err)
		assert.Empty(t, mgr.RuleGroups())
	})

	t.Run("valid rule file loads successfully", func(t *testing.T) {
		dir := t.TempDir()
		alertsFile := filepath.Join(dir, "alerts.yaml")

		rulesYAML := `groups:
  - name: test-group
    rules:
      - alert: TestAlert
        expr: up == 0
        for: 1m
        labels:
          alert_rule_id: "42"
          severity: critical
`
		require.NoError(t, os.WriteFile(alertsFile, []byte(rulesYAML), 0o644))

		err := libprom.ReloadRules(mgr, 15*time.Second, alertsFile)
		require.NoError(t, err)
		assert.Len(t, mgr.RuleGroups(), 1)
	})

	t.Run("invalid file returns error", func(t *testing.T) {
		err := libprom.ReloadRules(mgr, 15*time.Second, "/nonexistent/alerts.yaml")
		require.Error(t, err)
	})
}

func TestExtractAlertStates(t *testing.T) {
	reg := prometheusreg.NewRegistry()
	db, err := libprom.NewInMemoryTSDB(reg)
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()

	engine := libprom.NewEngine()

	mgr := libprom.NewRuleManager(libprom.RuleManagerConfig{
		Engine:     engine,
		Queryable:  db,
		Appendable: db,
		NotifyFunc: func(_ context.Context, _ string, _ ...*rules.Alert) {},
		Context:    context.Background(),
		Registerer: reg,
	})

	t.Run("no rules returns nil", func(t *testing.T) {
		states := libprom.ExtractAlertStates(mgr)
		assert.Nil(t, states)
	})

	t.Run("loaded rules return states", func(t *testing.T) {
		dir := t.TempDir()
		alertsFile := filepath.Join(dir, "alerts.yaml")

		rulesYAML := `groups:
  - name: test-group
    rules:
      - alert: TestAlert
        expr: up == 0
        for: 1m
        labels:
          alert_rule_id: "7"
          severity: warning
`
		require.NoError(t, os.WriteFile(alertsFile, []byte(rulesYAML), 0o644))
		require.NoError(t, libprom.ReloadRules(mgr, 15*time.Second, alertsFile))

		states := libprom.ExtractAlertStates(mgr)
		require.Len(t, states, 1)
		assert.Equal(t, 7, states[0].RuleID)
		assert.Equal(t, pkgmetrics.AlertRuleStateOK, states[0].State)
	})
}
