// Code generated by go generate; DO NOT EDIT.
// +build linux_bpf

package runtime

import (
	"github.com/DataDog/datadog-agent/pkg/ebpf"
)

var RuntimeSecurity = ebpf.NewRuntimeAsset("runtime-security.c", "8eb3caaa58b3010dd07d9e54731d08c8a649188283ef4ed665f1105947a9c736")
