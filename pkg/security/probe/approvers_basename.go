// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build linux

package probe

import (
	"path"

	"github.com/DataDog/datadog-agent/pkg/security/rules"
)

func onNewBasenameApprovers(probe *Probe, eventType EventType, field string, approvers rules.Approvers) ([]activeApprover, error) {
	stringValues := func(fvs rules.FilterValues) []string {
		var values []string
		for _, v := range fvs {
			values = append(values, v.Value.(string))
		}
		return values
	}

	prefix := eventType.String()
	if field != "" {
		prefix += "." + field
	}

	var basenameApprovers []activeApprover
	for field, values := range approvers {
		switch field {
		case prefix + ".basename":
			activeApprovers, err := approveBasenames("basename_approvers", eventType, stringValues(values)...)
			if err != nil {
				return nil, err
			}
			basenameApprovers = append(basenameApprovers, activeApprovers...)

		case prefix + ".filename":
			for _, value := range stringValues(values) {
				basename := path.Base(value)
				activeApprover, err := approveBasename("basename_approvers", eventType, basename)
				if err != nil {
					return nil, err
				}
				basenameApprovers = append(basenameApprovers, activeApprover)
			}
		}
	}

	return basenameApprovers, nil
}
