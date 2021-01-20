// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build !windows,!android

package main

import (
	"os"

	"golang.org/x/sys/unix"

	"github.com/DataDog/datadog-agent/cmd/agent/app"
)

func main() {
	err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})

	if err != nil {
		panic(err)
	}

	// Invoke the Agent
	if err := app.AgentCmd.Execute(); err != nil {
		os.Exit(-1)
	}
}
