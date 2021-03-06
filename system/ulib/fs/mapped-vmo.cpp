// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fs/mapped-vmo.h>
#include <zircon/process.h>
#include <zircon/syscalls.h>
#include <fbl/algorithm.h>
#include <fbl/alloc_checker.h>
#include <fbl/unique_ptr.h>

zx_status_t MappedVmo::Create(size_t size, const char* name, fbl::unique_ptr<MappedVmo>* out) {
    zx_handle_t vmo;
    uintptr_t addr;
    zx_status_t status;
    if ((status = zx_vmo_create(size, 0, &vmo)) != ZX_OK) {
        return status;
    } else if ((status = zx_vmar_map(zx_vmar_root_self(), 0, vmo, 0,
                                     size, ZX_VM_FLAG_PERM_READ | ZX_VM_FLAG_PERM_WRITE,
                                     &addr)) != ZX_OK) {
        zx_handle_close(vmo);
        return status;
    }

    zx_object_set_property(vmo, ZX_PROP_NAME, name, strlen(name));

    fbl::AllocChecker ac;
    fbl::unique_ptr<MappedVmo> mvmo(new (&ac) MappedVmo(vmo, addr, size));
    if (!ac.check()) {
        zx_vmar_unmap(zx_vmar_root_self(), addr, size);
        zx_handle_close(vmo);
        return ZX_ERR_NO_MEMORY;
    }

    *out = fbl::move(mvmo);
    return ZX_OK;
}

zx_status_t MappedVmo::Shrink(size_t off, size_t len) {
    if (len == 0 || off + len > len_ || off > len_ || off + len < off) {
        return ZX_ERR_INVALID_ARGS;
    }

    zx_status_t status;
    zx_handle_t new_vmo;
    if (off > 0) {
        // Unmap everything before the offset
        if ((status = zx_vmar_unmap(zx_vmar_root_self(), addr_, off)) != ZX_OK) {
            return status;
        }
    }
    if (off + len < len_) {
        // Unmap everything after the offset
        if ((status = zx_vmar_unmap(zx_vmar_root_self(), addr_ + off + len, len_ - (off + len))) != ZX_OK) {
            return status;
        }
    }
    if ((status = zx_vmo_clone(vmo_, ZX_VMO_CLONE_COPY_ON_WRITE, off, len, &new_vmo)) != ZX_OK) {
        return status;
    }
    zx_handle_close(vmo_);
    vmo_ = new_vmo;
    addr_ = addr_ + off;
    len_ = len;
    return ZX_OK;
}

zx_status_t MappedVmo::Grow(size_t len) {
    if (len < len_) {
        return ZX_ERR_INVALID_ARGS;
    }

    len = fbl::round_up(len, static_cast<size_t>(PAGE_SIZE));
    zx_status_t status;
    uintptr_t addr;

    if ((status = zx_vmo_set_size(vmo_, len)) != ZX_OK) {
        return status;
    }

    zx_info_vmar_t vmar_info;
    if ((status = zx_object_get_info(zx_vmar_root_self(), ZX_INFO_VMAR, &vmar_info, sizeof(vmar_info), NULL, NULL)) != ZX_OK) {
        return status;
    }

    // Try to extend mapping
    if ((status = zx_vmar_map(zx_vmar_root_self(), addr_ + len_ - vmar_info.base, vmo_, len_, len - len_, ZX_VM_FLAG_PERM_READ | ZX_VM_FLAG_PERM_WRITE | ZX_VM_FLAG_SPECIFIC, &addr)) != ZX_OK) {
        // If extension fails, create entirely new mapping and unmap the old one
        if ((status = zx_vmar_map(zx_vmar_root_self(), 0, vmo_, 0, len, ZX_VM_FLAG_PERM_READ | ZX_VM_FLAG_PERM_WRITE, &addr)) != ZX_OK) {
            return status;
        }

        if ((status = zx_vmar_unmap(zx_vmar_root_self(), addr_, len_)) != ZX_OK) {
            return status;
        }

        addr_ = addr;
    }

    len_ = len;
    return ZX_OK;
}

zx_handle_t MappedVmo::GetVmo(void) const {
    return vmo_;
}
void* MappedVmo::GetData(void) const {
    return (void*)addr_;
}

size_t MappedVmo::GetSize(void) const {
    return len_;
}

MappedVmo::MappedVmo(zx_handle_t vmo, uintptr_t addr, size_t len)
    : vmo_(vmo), addr_(addr), len_(len) {}

MappedVmo::~MappedVmo() {
    zx_vmar_unmap(zx_vmar_root_self(), addr_, len_);
    zx_handle_close(vmo_);
}
