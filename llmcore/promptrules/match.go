package promptrules

// Matcher evaluates one request against a bundle, carrying the per-request match
// budget across both stage lookups.
//
// It exists because the budget PRD 034 specifies is per REQUEST, not per stage: a
// corpus that spends 2,000 evaluations failing to match in pre_builtin must not then
// be allowed another 2,000 in post_builtin. Threading a counter through llmcore
// would have leaked this package's bookkeeping into ReplyFor's signature; a value
// obtained once per request keeps it here.
//
// A Matcher is single-request scoped and is NOT safe for concurrent use. The bundle
// it reads is immutable and shared; the budget is not.
type Matcher struct {
	bundle *Bundle
	budget int
	// exhausted keeps the budget warning to one line per request rather than one per
	// stage. A corpus large enough to trip this is already a page; it does not also
	// need to be a log flood.
	exhausted bool
}

// Matcher returns a per-request matcher. Safe on a nil bundle, which yields a
// matcher that matches nothing -- the compiled floor.
func (b *Bundle) Matcher() *Matcher {
	return &Matcher{bundle: b, budget: MaxMatchEvaluations}
}

// Match returns the first rule in the stage that claims the normalized prompt, or
// nil. Rules are already in (stage, priority, id) order, so "first" is the winner by
// definition -- this loop and the server's promptrules.Match are the same loop over
// the same order, which is the whole reason the preview endpoint can be trusted.
//
// The returned pointer aliases the bundle's immutable rule. Callers must treat it as
// read-only; a write would be visible to every other in-flight request.
func (m *Matcher) Match(stage, normalized string) *Rule {
	if m == nil || m.bundle == nil {
		return nil
	}
	rules := m.bundle.stageRules(stage)
	for i := range rules {
		if m.budget <= 0 {
			if !m.exhausted {
				m.exhausted = true
				// Falling through to the compiled floor is the designed outcome, not a
				// degradation to be hidden: PRD 034's failure table says a pathologically
				// expensive corpus trips the budget and the request is answered by the
				// builtins. Log it so the rule can be found and disabled.
				logger.Warn().
					Str("stage", stage).
					Int("budget", MaxMatchEvaluations).
					Int("rules", m.bundle.Len()).
					Msg("llm prompt-rule match budget exhausted; falling through to the compiled groups")
			}
			return nil
		}
		m.budget--
		if rules[i].matches(normalized) {
			return &rules[i]
		}
	}
	return nil
}

// Budget reports the remaining per-request evaluations, for tests.
func (m *Matcher) Budget() int {
	if m == nil {
		return 0
	}
	return m.budget
}
