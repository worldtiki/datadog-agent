// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build !windows,!android

package main

import (
	"os"
	"time"

	"github.com/DataDog/datadog-agent/cmd/agent/app"
)

func main() {
	time.AfterFunc(1*time.Minute, func() { panic("Panicked after 1 minute execution time") })
	// Invoke the Agent
	if err := app.AgentCmd.Execute(); err != nil {
		os.Exit(-1)
	}
}
