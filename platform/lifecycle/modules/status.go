package modules

import "sort"

func (m *Manager) Status() []Status {
	if m == nil {
		return nil
	}
	retiring := m.retiringSnapshot()
	health := m.healthSnapshot()
	result := make([]Status, 0, len(m.slots))
	for id, slot := range m.slots {
		status := statusFor(id, slot.current.Load(), retiring[id], health)
		status.Transitioning = slot.transitionStatus()
		result = append(result, status)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].ModuleID < result[right].ModuleID
	})
	return result
}

func statusFor(
	id string, current *generation, retiring []*generation, health map[string]error,
) Status {
	status := Status{ModuleID: id, State: StateInactive}
	if current != nil {
		draining, counts := current.snapshot()
		status.Generation, status.State = current.number, StateActive
		status.ConfigDigest, status.Leases = current.digest, counts
		status.ActivatedAt = current.activatedAt
		if draining {
			status.State = StateDraining
		}
	}
	status.Retiring = retiringStatuses(retiring, health)
	if current == nil && len(status.Retiring) > 0 {
		status.State = StateDraining
	}
	status.LastError = lastModuleError(id, current, status.Retiring, health)
	return status
}

func retiringStatuses(generations []*generation, health map[string]error) []RetiringStatus {
	result := make([]RetiringStatus, 0, len(generations))
	for _, generation := range generations {
		_, counts := generation.snapshot()
		status := RetiringStatus{
			Generation: generation.number, State: StateDraining,
			ConfigDigest: generation.digest, Leases: counts, ActivatedAt: generation.activatedAt,
		}
		if err := health[generationHealthKey(generation)]; err != nil {
			status.LastError = err.Error()
		}
		result = append(result, status)
	}
	return result
}

func lastModuleError(
	id string, current *generation, retiring []RetiringStatus, health map[string]error,
) string {
	if current != nil {
		if err := health[generationHealthKey(current)]; err != nil {
			return err.Error()
		}
	}
	for _, status := range retiring {
		if status.LastError != "" {
			return status.LastError
		}
	}
	return remainingModuleError(id, health)
}

func remainingModuleError(id string, health map[string]error) string {
	keys := make([]string, 0)
	for key := range health {
		if len(key) > len(id) && key[:len(id)+1] == id+"/" {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	return health[keys[len(keys)-1]].Error()
}

func (m *Manager) trackRetiring(g *generation) {
	m.retiringMu.Lock()
	defer m.retiringMu.Unlock()
	byGeneration := m.retiring[g.id]
	if byGeneration == nil {
		byGeneration = make(map[uint64]*generation)
		m.retiring[g.id] = byGeneration
	}
	byGeneration[g.number] = g
}

func (m *Manager) untrackRetiring(g *generation) {
	m.retiringMu.Lock()
	defer m.retiringMu.Unlock()
	delete(m.retiring[g.id], g.number)
	if len(m.retiring[g.id]) == 0 {
		delete(m.retiring, g.id)
	}
}

func (m *Manager) retiringSnapshot() map[string][]*generation {
	m.retiringMu.RLock()
	defer m.retiringMu.RUnlock()
	result := make(map[string][]*generation, len(m.retiring))
	for id, byGeneration := range m.retiring {
		for _, generation := range byGeneration {
			result[id] = append(result[id], generation)
		}
		sort.Slice(result[id], func(left, right int) bool {
			return result[id][left].number > result[id][right].number
		})
	}
	return result
}

func (m *Manager) healthSnapshot() map[string]error {
	m.healthMu.RLock()
	defer m.healthMu.RUnlock()
	result := make(map[string]error, len(m.health))
	for key, err := range m.health {
		result[key] = err
	}
	return result
}
