// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build docker,!windows

package docker

import "golang.org/x/sys/unix"

const (
	basePath = "/var/lib/docker/containers"
)

func checkReadAccess() error {
	return unix.Access(basePath, unix.X_OK)
}
