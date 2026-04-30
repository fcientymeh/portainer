package libprometheus

import (
	"context"
	"strconv"
	"time"

	pkgmetrics "github.com/portainer/portainer/pkg/metrics"
	prometheusreg "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/rules"
	"github.com/prometheus/prometheus/storage"
)

// RuleManagerConfig holds the parameters needed to construct a Prometheus rules.Manager.
type RuleManagerConfig struct {
	Engine     *promql.Engine
	Queryable  storage.Queryable
	Appendable storage.Appendable
	NotifyFunc rules.NotifyFunc
	Context    context.Context
	Registerer prometheusreg.Registerer
}

// NewRuleManager constructs a Prometheus rules.Manager from the given config.
func NewRuleManager(cfg RuleManagerConfig) *rules.Manager {
	return rules.NewManager(&rules.ManagerOptions{
		QueryFunc:  rules.EngineQueryFunc(cfg.Engine, cfg.Queryable),
		Appendable: cfg.Appendable,
		Queryable:  cfg.Queryable,
		NotifyFunc: cfg.NotifyFunc,
		Context:    cfg.Context,
		Logger:     NewZerologSlogger(),
		Registerer: cfg.Registerer,
	})
}

// ReloadRules updates the active rule set on a rules.Manager from a YAML file.
// Pass an empty alertsFilePath to clear all rules.
func ReloadRules(mgr *rules.Manager, evalInterval time.Duration, alertsFilePath string) error {
	var files []string
	if alertsFilePath != "" {
		files = []string{alertsFilePath}
	}

	return mgr.Update(evalInterval, files, labels.EmptyLabels(), "", nil)
}

// ExtractAlertStates returns the current evaluation state for each alerting rule
// managed by the given rules.Manager.
func ExtractAlertStates(mgr *rules.Manager) []pkgmetrics.EdgeAlertRuleState {
	var states []pkgmetrics.EdgeAlertRuleState

	for _, group := range mgr.RuleGroups() {
		for _, rule := range group.Rules() {
			alertRule, ok := rule.(*rules.AlertingRule)
			if !ok {
				continue
			}

			ruleIDStr := alertRule.Labels().Get(pkgmetrics.AlertRuleIDLabel)
			ruleID, err := strconv.Atoi(ruleIDStr)
			if err != nil || ruleID <= 0 {
				continue
			}

			state := pkgmetrics.AlertRuleStateOK
			for _, a := range alertRule.ActiveAlerts() {
				switch a.State {
				case rules.StateFiring:
					state = pkgmetrics.AlertRuleStateFiring
				case rules.StatePending:
					if state != pkgmetrics.AlertRuleStateFiring {
						state = pkgmetrics.AlertRuleStatePending
					}
				}
			}

			var lastErr string
			if alertRule.LastError() != nil {
				lastErr = alertRule.LastError().Error()
			}

			states = append(states, pkgmetrics.EdgeAlertRuleState{
				RuleID:         ruleID,
				State:          state,
				LastEvaluation: alertRule.GetEvaluationTimestamp().UnixMilli(),
				LastError:      lastErr,
			})
		}
	}

	return states
}
