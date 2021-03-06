// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <err.h>
#include <inttypes.h>
#include <platform.h>
#include <stdint.h>
#include <stdlib.h>
#include <trace.h>

#include <lib/user_copy/user_ptr.h>
#include <object/fifo_dispatcher.h>
#include <object/handle_owner.h>
#include <object/handles.h>
#include <object/process_dispatcher.h>

#include <zircon/syscalls/policy.h>
#include <fbl/ref_ptr.h>

#include "syscalls_priv.h"

#define LOCAL_TRACE 0

zx_status_t sys_fifo_create(uint32_t count, uint32_t elemsize, uint32_t options,
                            user_out_ptr<zx_handle_t> out0, user_out_ptr<zx_handle_t> out1) {
    auto up = ProcessDispatcher::GetCurrent();
    zx_status_t res = up->QueryPolicy(ZX_POL_NEW_FIFO);
    if (res != ZX_OK)
        return res;

    fbl::RefPtr<Dispatcher> dispatcher0;
    fbl::RefPtr<Dispatcher> dispatcher1;
    zx_rights_t rights;
    zx_status_t result = FifoDispatcher::Create(count, elemsize, options,
                                                &dispatcher0, &dispatcher1, &rights);
    if (result != ZX_OK)
        return result;

    HandleOwner handle0(MakeHandle(fbl::move(dispatcher0), rights));
    if (!handle0)
        return ZX_ERR_NO_MEMORY;
    HandleOwner handle1(MakeHandle(fbl::move(dispatcher1), rights));
    if (!handle1)
        return ZX_ERR_NO_MEMORY;

    if (out0.copy_to_user(up->MapHandleToValue(handle0)) != ZX_OK)
        return ZX_ERR_INVALID_ARGS;
    if (out1.copy_to_user(up->MapHandleToValue(handle1)) != ZX_OK)
        return ZX_ERR_INVALID_ARGS;

    up->AddHandle(fbl::move(handle0));
    up->AddHandle(fbl::move(handle1));

    return ZX_OK;
}

zx_status_t sys_fifo_write(zx_handle_t handle, user_in_ptr<const void> entries,
                           size_t len, user_out_ptr<uint32_t> actual_out) {
    auto up = ProcessDispatcher::GetCurrent();

    fbl::RefPtr<FifoDispatcher> fifo;
    zx_status_t status = up->GetDispatcherWithRights(handle, ZX_RIGHT_WRITE, &fifo);
    if (status != ZX_OK)
        return status;

    uint32_t actual;
    status = fifo->WriteFromUser(entries.reinterpret<const uint8_t>(), len, &actual);
    if (status != ZX_OK)
        return status;

    if (actual_out.copy_to_user(actual) != ZX_OK)
        return ZX_ERR_INVALID_ARGS;

    return ZX_OK;
}

zx_status_t sys_fifo_read(zx_handle_t handle, user_out_ptr<void> entries, size_t len,
                          user_out_ptr<uint32_t> actual_out) {
    auto up = ProcessDispatcher::GetCurrent();

    fbl::RefPtr<FifoDispatcher> fifo;
    zx_status_t status = up->GetDispatcherWithRights(handle, ZX_RIGHT_READ, &fifo);
    if (status != ZX_OK)
        return status;

    uint32_t actual;
    status = fifo->ReadToUser(entries.reinterpret<uint8_t>(), len, &actual);
    if (status != ZX_OK)
        return status;

    if (actual_out.copy_to_user(actual) != ZX_OK)
        return ZX_ERR_INVALID_ARGS;

    return ZX_OK;
}
