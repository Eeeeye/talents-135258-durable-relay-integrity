package config

import (
	"fmt"
	"sync"
	"sync/atomic"
)

type Snapshot struct {
	Generation uint64 `json:"generation"`
	Config
}

type Manager struct {
	path       string
	reloadMu   sync.Mutex
	generation atomic.Uint64
	current    atomic.Pointer[Config]
}

func NewManager(path string, initial Config) *Manager {
	m := &Manager{path: path}
	copyOfInitial := initial
	m.current.Store(&copyOfInitial)
	m.generation.Store(1)
	return m
}

func (m *Manager) Current() Snapshot {
	cfg := *m.current.Load()
	return Snapshot{Generation: m.generation.Load(), Config: cfg}
}

func (m *Manager) Reload() (Snapshot, error) {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	next, err := LoadFile(m.path)
	if err != nil {
		return m.Current(), err
	}
	previous := *m.current.Load()
	if err := previous.ImmutableEqual(next); err != nil {
		return m.Current(), fmt.Errorf("reject reload: %w", err)
	}
	copyOfNext := next
	m.current.Store(&copyOfNext)
	generation := m.generation.Add(1)
	return Snapshot{Generation: generation, Config: next}, nil
}

func (m *Manager) Path() string {
	return m.path
}
