package config

import (
	"fmt"
	"sync"
)

type Snapshot struct {
	Generation uint64 `json:"generation"`
	Config
}

type Manager struct {
	path       string
	mu         sync.RWMutex
	generation uint64
	current    Config
}

func NewManager(path string, initial Config) *Manager {
	return &Manager{path: path, generation: 1, current: initial}
}

func (m *Manager) Current() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Snapshot{Generation: m.generation, Config: m.current}
}

func (m *Manager) Reload() (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	next, err := LoadFile(m.path)
	if err != nil {
		return Snapshot{Generation: m.generation, Config: m.current}, err
	}
	if err := m.current.ImmutableEqual(next); err != nil {
		return Snapshot{Generation: m.generation, Config: m.current}, fmt.Errorf("reject reload: %w", err)
	}
	m.current = next
	m.generation++
	return Snapshot{Generation: m.generation, Config: next}, nil
}

func (m *Manager) Path() string {
	return m.path
}
