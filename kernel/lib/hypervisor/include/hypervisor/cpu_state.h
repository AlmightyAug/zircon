// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#pragma once

#include <bitmap/raw-bitmap.h>
#include <bitmap/storage.h>
#include <kernel/cpu.h>
#include <kernel/thread.h>

namespace hypervisor {

/* Provides a base class for arch-specific CPU state logic.
 *
 * |T| is the type of the ID, and is an integral type.
 * |N| is the maximum value of an ID.
 */
template <typename T, T N>
class CpuState {
public:
    zx_status_t AllocId(T* id) {
        size_t first_unset;
        bool all_set = id_bitmap_.Get(0, N, &first_unset);
        if (all_set)
            return ZX_ERR_NO_RESOURCES;
        if (first_unset >= N)
            return ZX_ERR_OUT_OF_RANGE;
        *id = static_cast<T>(first_unset + 1);
        return id_bitmap_.SetOne(first_unset);
    }

    zx_status_t FreeId(T id) {
        if (id == 0 || !id_bitmap_.GetOne(id - 1))
            return ZX_ERR_INVALID_ARGS;
        return id_bitmap_.ClearOne(id - 1);
    }

protected:
    zx_status_t Init() {
        return id_bitmap_.Reset(N);
    }

private:
    bitmap::RawBitmapGeneric<bitmap::FixedStorage<N>> id_bitmap_;
};

} // namespace hypervisor

typedef zx_status_t (* percpu_task_t)(void* context, cpu_num_t cpu_num);

/* Executes a task on each online CPU, and returns a CPU mask containing each
 * CPU the task was successfully run on. */
cpu_mask_t percpu_exec(percpu_task_t task, void* context);

/* Pin the current thread to a CPU, and reschedule it to execute on that CPU. */
thread_t* pin_thread(cpu_num_t cpu);
