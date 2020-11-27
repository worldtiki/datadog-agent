// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

// +build linux

package probe

import (
	"time"

	libebpf "github.com/DataDog/ebpf"
	"github.com/pkg/errors"

	"github.com/DataDog/datadog-agent/pkg/security/rules"
	"github.com/DataDog/datadog-agent/pkg/security/secl/eval"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	// discarderRevisionSize array size used to store discarder revisions
	discarderRevisionSize = 4096
)

// Discarder represents a discarder which is basically the field that we know for sure
// that the value will be always rejected by the rules
type Discarder struct {
	Field eval.Field
}

type onDiscarderHandler func(rs *rules.RuleSet, event *Event, probe *Probe, discarder Discarder) error

var (
	allDiscarderHandlers = make(map[eval.EventType]onDiscarderHandler)
	// SupportedDiscarders lists all field which supports discarders
	SupportedDiscarders = make(map[eval.Field]bool)
)

type pidDiscarderParameters struct {
	EventType  EventType
	Timestamps [maxEventRoundedUp]uint64
}

func (p *Probe) discardPID(eventType EventType, pid uint32) error {
	var params pidDiscarderParameters

	updateFlags := libebpf.UpdateExist
	if err := p.pidDiscarders.Lookup(pid, &params); err != nil {
		updateFlags = libebpf.UpdateAny
	}

	params.EventType |= 1 << (eventType - 1)
	return p.pidDiscarders.Update(pid, &params, updateFlags)
}

func (p *Probe) discardPIDWithTimeout(eventType EventType, pid uint32, timeout time.Duration) error {
	var params pidDiscarderParameters

	updateFlags := libebpf.UpdateExist
	if err := p.pidDiscarders.Lookup(pid, &params); err != nil {
		updateFlags = libebpf.UpdateAny
	}

	params.EventType |= 1 << (eventType - 1)
	params.Timestamps[eventType] = uint64(p.resolvers.TimeResolver.ComputeMonotonicTimestamp(time.Now().Add(timeout)))

	return p.pidDiscarders.Update(pid, &params, updateFlags)
}

type inodeDiscarder struct {
	PathKey  PathKey
	Revision uint32
	Padding  uint32
}

type inodeDiscarderParameters struct {
	EventType EventType
}

func (p *Probe) removeDiscarderInode(mountID uint32, inode uint64) {
	key := inodeDiscarder{
		PathKey: PathKey{
			MountID: mountID,
			Inode:   inode,
		},
	}
	_ = p.inodeDiscarders.Delete(&key)
}

func (p *Probe) discardInode(eventType EventType, mountID uint32, inode uint64) error {
	var params inodeDiscarderParameters
	key := inodeDiscarder{
		PathKey: PathKey{
			MountID: mountID,
			Inode:   inode,
		},
		Revision: p.getDiscarderRevision(mountID),
	}

	updateFlags := libebpf.UpdateExist
	if err := p.inodeDiscarders.Lookup(key, &params); err != nil {
		updateFlags = libebpf.UpdateAny
	}

	params.EventType |= 1 << (eventType - 1)
	return p.inodeDiscarders.Update(&key, &params, updateFlags)
}

func (p *Probe) discardParentInode(rs *rules.RuleSet, eventType EventType, field eval.Field, filename string, mountID uint32, inode uint64, pathID uint32) (bool, uint32, uint64, error) {
	isDiscarder, err := isParentPathDiscarder(rs, p.regexCache, eventType, field, filename)
	if !isDiscarder {
		return false, 0, 0, err
	}

	parentMountID, parentInode, err := p.resolvers.DentryResolver.GetParent(mountID, inode, pathID)
	if err != nil {
		return false, 0, 0, err
	}

	if err := p.discardInode(eventType, parentMountID, parentInode); err != nil {
		return false, 0, 0, err
	}

	return true, parentMountID, parentInode, nil
}

// function used to retrieve discarder information, *.filename, mountID, inode, file deleted
type inodeEventGetter = func(event *Event) (eval.Field, uint32, uint64, uint32, bool)

func filenameDiscarderWrapper(eventType EventType, handler onDiscarderHandler, getter inodeEventGetter) onDiscarderHandler {
	return func(rs *rules.RuleSet, event *Event, probe *Probe, discarder Discarder) error {
		field, mountID, inode, pathID, isDeleted := getter(event)

		if discarder.Field == field {
			value, err := event.GetFieldValue(field)
			if err != nil {
				return err
			}
			filename := value.(string)

			if filename == "" {
				return nil
			}

			if probe.IsInvalidDiscarder(field, filename) {
				return nil
			}

			isDiscarded, _, parentInode, err := probe.discardParentInode(rs, eventType, field, filename, mountID, inode, pathID)
			if !isDiscarded && !isDeleted {
				if _, ok := err.(*ErrInvalidKeyPath); !ok {
					log.Tracef("Apply `%s.filename` inode discarder for event `%s`, inode: %d", eventType, eventType, inode)

					// not able to discard the parent then only discard the filename
					err = probe.discardInode(eventType, mountID, inode)
				}
			} else {
				log.Tracef("Apply `%s.filename` parent inode discarder for event `%s` with value `%s`", eventType, eventType, filename)
			}

			if err != nil {
				err = errors.Wrapf(err, "unable to set inode discarders for `%s` for event `%s`, inode: %d", filename, eventType, parentInode)
			}

			return err
		}

		if handler != nil {
			return handler(rs, event, probe, discarder)
		}

		return nil
	}
}

func init() {
	SupportedDiscarders["process.filename"] = true

	allDiscarderHandlers["open"] = processDiscarderWrapper(FileOpenEventType,
		filenameDiscarderWrapper(FileOpenEventType, nil,
			func(event *Event) (eval.Field, uint32, uint64, uint32, bool) {
				return "open.filename", event.Open.MountID, event.Open.Inode, event.Open.PathID, false
			}))
	SupportedDiscarders["open.filename"] = true

	allDiscarderHandlers["mkdir"] = processDiscarderWrapper(FileMkdirEventType,
		filenameDiscarderWrapper(FileMkdirEventType, nil,
			func(event *Event) (eval.Field, uint32, uint64, uint32, bool) {
				return "mkdir.filename", event.Mkdir.MountID, event.Mkdir.Inode, event.Mkdir.PathID, false
			}))
	SupportedDiscarders["mkdir.filename"] = true

	allDiscarderHandlers["link"] = processDiscarderWrapper(FileLinkEventType, nil)

	allDiscarderHandlers["rename"] = processDiscarderWrapper(FileRenameEventType, nil)

	allDiscarderHandlers["unlink"] = processDiscarderWrapper(FileUnlinkEventType,
		filenameDiscarderWrapper(FileUnlinkEventType, nil,
			func(event *Event) (eval.Field, uint32, uint64, uint32, bool) {
				return "unlink.filename", event.Unlink.MountID, event.Unlink.Inode, event.Unlink.PathID, true
			}))
	SupportedDiscarders["unlink.filename"] = true

	allDiscarderHandlers["rmdir"] = processDiscarderWrapper(FileRmdirEventType,
		filenameDiscarderWrapper(FileRmdirEventType, nil,
			func(event *Event) (eval.Field, uint32, uint64, uint32, bool) {
				return "rmdir.filename", event.Rmdir.MountID, event.Rmdir.Inode, event.Rmdir.PathID, false
			}))
	SupportedDiscarders["rmdir.filename"] = true

	allDiscarderHandlers["chmod"] = processDiscarderWrapper(FileChmodEventType,
		filenameDiscarderWrapper(FileChmodEventType, nil,
			func(event *Event) (eval.Field, uint32, uint64, uint32, bool) {
				return "chmod.filename", event.Chmod.MountID, event.Chmod.Inode, event.Chmod.PathID, false
			}))
	SupportedDiscarders["chmod.filename"] = true

	allDiscarderHandlers["chown"] = processDiscarderWrapper(FileChownEventType,
		filenameDiscarderWrapper(FileChownEventType, nil,
			func(event *Event) (eval.Field, uint32, uint64, uint32, bool) {
				return "chown.filename", event.Chown.MountID, event.Chown.Inode, event.Chown.PathID, false
			}))
	SupportedDiscarders["chown.filename"] = true

	allDiscarderHandlers["utimes"] = processDiscarderWrapper(FileUtimeEventType,
		filenameDiscarderWrapper(FileUtimeEventType, nil,
			func(event *Event) (eval.Field, uint32, uint64, uint32, bool) {
				return "utimes.filename", event.Utimes.MountID, event.Utimes.Inode, event.Utimes.PathID, false
			}))
	SupportedDiscarders["utimes.filename"] = true

	allDiscarderHandlers["setxattr"] = processDiscarderWrapper(FileSetXAttrEventType,
		filenameDiscarderWrapper(FileSetXAttrEventType, nil,
			func(event *Event) (eval.Field, uint32, uint64, uint32, bool) {
				return "setxattr.filename", event.SetXAttr.MountID, event.SetXAttr.Inode, event.SetXAttr.PathID, false
			}))
	SupportedDiscarders["setxattr.filename"] = true

	allDiscarderHandlers["removexattr"] = processDiscarderWrapper(FileRemoveXAttrEventType,
		filenameDiscarderWrapper(FileRemoveXAttrEventType, nil,
			func(event *Event) (eval.Field, uint32, uint64, uint32, bool) {
				return "removexattr.filename", event.RemoveXAttr.MountID, event.RemoveXAttr.Inode, event.RemoveXAttr.PathID, false
			}))
	SupportedDiscarders["removexattr.filename"] = true
}
