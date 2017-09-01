// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <ddk/device.h>
#include <ddk/debug.h>
#include <ddk/driver.h>
#include <ddk/protocol/pci.h>

#include <magenta/types.h>

#include <intel-serialio/serialio.h>

#define UART_RESETS_MASK 0x3u
#define UART_RESETS_IN_RESET 0x0u
#define UART_RESETS_RELEASE_RESET 0x3u

#define UART_CLOCKS_CLK_UPDATE (1u << 31)
#define UART_CLOCKS_N_VAL(val) ((val) << 16)
#define UART_CLOCKS_M_VAL(val) ((val) << 1)
#define UART_CLOCKS_CLK_EN 1u

mx_status_t intel_serialio_bind_uart(mx_device_t* dev) {
    pci_protocol_t pci;
    if (device_get_protocol(dev, MX_PROTOCOL_PCI, &pci)) {
        return MX_ERR_NOT_SUPPORTED;
    }

    mx_handle_t config_handle = MX_HANDLE_INVALID;
    mx_handle_t regs_handle = MX_HANDLE_INVALID;

    const pci_config_t* pci_config;
    size_t config_size;
    mx_status_t status = pci_map_resource(&pci, PCI_RESOURCE_CONFIG,
                                          MX_CACHE_POLICY_UNCACHED_DEVICE,
                                          (void**)&pci_config, &config_size,
                                          &config_handle);
    if (status != MX_OK) {
        dprintf(ERROR, "uart: failed to map pci config: %d\n", status);
        goto fail;
    }

    void* regs;
    size_t regs_size;
    status = pci_map_resource(&pci, PCI_RESOURCE_BAR_0, MX_CACHE_POLICY_UNCACHED_DEVICE,
                              (void**)&regs, &regs_size, &regs_handle);
    if (status != MX_OK) {
        dprintf(ERROR, "uart: failed to map pci bar 0: %d\n", status);
        goto fail;
    }

    status = pci_enable_bus_master(&pci, true);
    if (status != MX_OK) {
        dprintf(ERROR, "uart: failed to enable bus master: %d\n", status);
        goto fail;
    }

    if (pci_config->vendor_id == INTEL_VID &&
        (pci_config->device_id == INTEL_SUNRISE_POINT_SERIALIO_UART0_DID ||
         pci_config->device_id == INTEL_SUNRISE_POINT_SERIALIO_UART1_DID)) {

        volatile struct {
            uint8_t pad[0x200];
            uint32_t clocks;
            uint32_t resets;
        } *real_regs = regs;

        // Check if UART is being held in reset.  If so, let's set it up.
        if ((real_regs->resets & UART_RESETS_MASK) == UART_RESETS_IN_RESET) {
            dprintf(INFO, "uart: resetting\n");
            // Take controller out of reset
            real_regs->resets = UART_RESETS_RELEASE_RESET;

            // Configure the clock
            real_regs->clocks = UART_CLOCKS_CLK_UPDATE | UART_CLOCKS_CLK_EN |
                    UART_CLOCKS_M_VAL(0x30) | UART_CLOCKS_N_VAL(0xc35);
            dprintf(INFO, "uart: read back: %08x\n", real_regs->clocks);

            return MX_OK;

        }
        dprintf(INFO, "uart: was not in reset\n");
    }

    // Not implemented yet.
    status = MX_ERR_NOT_SUPPORTED;

fail:
    if (config_handle != MX_HANDLE_INVALID) {
        mx_handle_close(config_handle);
    }
    if (regs_handle != MX_HANDLE_INVALID) {
        mx_handle_close(regs_handle);
    }
    return status;
}
