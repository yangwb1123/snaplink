package modules

import (
	"context"
	"errors"
	"fmt"
	"time"
)

func (m *Manager) retire(generation *generation) *Retirement {
	m.trackRetiring(generation)
	retirement := newRetirement()
	m.retirementTasks.Add(1)
	go func() {
		defer m.retirementTasks.Done()
		retirement.complete(m.retireGeneration(generation))
	}()
	return retirement
}

func (m *Manager) retireGeneration(generation *generation) error {
	key := generationHealthKey(generation)
	timer := time.NewTimer(m.options.DrainTimeout)
	defer timer.Stop()
	select {
	case <-generation.drained:
	case <-timer.C:
		m.setHealth(key, ErrDrainTimeout)
		m.emitTransition(TransitionDrainTimedOut, generation, 0)
		<-generation.drained
		m.setHealth(key, nil)
	}
	return m.stopGeneration(generation)
}

func (m *Manager) stopGeneration(generation *generation) error {
	quiesceErr := m.callLifecycle(context.Background(), generation.instance.Quiesce)
	stopErr := m.callLifecycle(context.Background(), generation.instance.Stop)
	err := errors.Join(quiesceErr, stopErr)
	key := generationHealthKey(generation)
	if quiesceErr != nil {
		m.emitTransition(TransitionQuiesceFailed, generation, 0)
	}
	if stopErr != nil {
		m.emitTransition(TransitionStopFailed, generation, 0)
	} else {
		releaseGenerationDependencies(generation)
		m.untrackRetiring(generation)
		m.emitTransition(TransitionRetired, generation, 0)
	}
	if err != nil {
		m.setHealth(key, err)
	} else {
		m.setHealth(key, nil)
	}
	return err
}

func generationHealthKey(generation *generation) string {
	return fmt.Sprintf("%s/%d", generation.id, generation.number)
}

func (m *Manager) beginRetirement(
	generation *generation, kind TransitionEventType, related uint64,
) {
	generation.beginDrain()
	m.trackRetiring(generation)
	m.emitTransition(kind, generation, related)
}
