#ifndef _APPROVERS_H
#define _APPROVERS_H

#include "syscalls.h"

#define BASENAME_FILTER_SIZE 32

struct basename_t {
    char value[BASENAME_FILTER_SIZE];
};

struct bpf_map_def SEC("maps/basename_approvers") basename_approvers = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = BASENAME_FILTER_SIZE,
    .value_size = sizeof(struct filter_t),
    .max_entries = 255,
    .pinning = 0,
    .namespace = "",
};

void get_dentry_name(struct dentry *dentry, void *buffer, size_t n);

int __attribute__((always_inline)) approve_by_basename(struct dentry *dentry, u64 event_type) {
    struct basename_t basename = {};
    get_dentry_name(dentry, &basename, sizeof(basename));

    struct filter_t *filter = bpf_map_lookup_elem(&basename_approvers, &basename);
    bpf_printk("approve_by_basename %s, event %d\n", basename.value, event_type);
    if (filter && filter->event_mask & (1 << (event_type-1))) {
// #ifdef DEBUG
        bpf_printk("basename %s approved\n", basename.value);
// #endif
        return 1;
    }
    bpf_printk("basename %s disapproved\n", basename.value);
    return 0;
}

int __attribute__((always_inline)) basename_approver(struct syscall_cache_t *syscall, struct dentry *dentry, u64 event_type) {
    if ((syscall->policy.flags & BASENAME) > 0) {
        return approve_by_basename(dentry, event_type);
    }
    return 0;
}

#endif
