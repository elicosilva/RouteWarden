package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// RepoConfig identifies one target repository for the benchmark.
type RepoConfig struct {
	Owner string `yaml:"owner"`
	Name  string `yaml:"name"`
}

// BenchmarkConfig is the top-level shape of benchmark/repos.yaml.
type BenchmarkConfig struct {
	Repos []RepoConfig `yaml:"repos"`
}

func loadRepoConfig(path string) (*BenchmarkConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("benchmark: read repos config %q: %w", path, err)
	}

	var cfg BenchmarkConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("benchmark: parse repos config %q: %w", path, err)
	}
	if len(cfg.Repos) == 0 {
		return nil, fmt.Errorf("benchmark: repos config %q has no repos listed", path)
	}

	return &cfg, nil
}
