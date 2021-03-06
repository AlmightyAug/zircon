// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <ddk/debug.h>
#include <ddk/device.h>
#include <ddk/protocol/usb.h>
#include <ddk/protocol/usb-bus.h>
#include <ddk/protocol/usb-hci.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "usb-device.h"
#include "usb-interface.h"

// Represents a USB bus, which manages all devices for a USB host controller
typedef struct usb_bus {
    zx_device_t* zxdev;
    zx_device_t* hci_zxdev;
    usb_hci_protocol_t hci;

    // top-level USB devices, indexed by device_id
    usb_device_t** devices;
    size_t max_device_count;
} usb_bus_t;

static zx_status_t bus_add_device(void* ctx, uint32_t device_id, uint32_t hub_id,
                                      usb_speed_t speed) {
    usb_bus_t* bus = ctx;

    if (device_id >= bus->max_device_count) return ZX_ERR_INVALID_ARGS;

    usb_device_t* usb_device;
    zx_status_t result = usb_device_add(bus->hci_zxdev, &bus->hci, bus->zxdev, device_id,
                                        hub_id, speed, &usb_device);
    if (result == ZX_OK) {
        bus->devices[device_id] = usb_device;
    }
    return result;
}

static void bus_remove_device(void* ctx, uint32_t device_id) {
    usb_bus_t* bus = ctx;
    if (device_id >= bus->max_device_count) {
        zxlogf(ERROR, "device_id out of range in usb_bus_remove_device\n");
        return;
    }
    usb_device_t* device = bus->devices[device_id];
    if (device) {
        device_remove(device->zxdev);
        bus->devices[device_id] = NULL;
    }
}

static usb_bus_interface_ops_t _bus_interface = {
    .add_device = bus_add_device,
    .remove_device = bus_remove_device,
};

static zx_status_t bus_configure_hub(void* ctx, zx_device_t* hub_device, usb_speed_t speed,
                                         usb_hub_descriptor_t* descriptor) {
    usb_bus_t* bus = ctx;
    uint32_t hub_id;
    if (usb_interface_get_device_id(hub_device, &hub_id) != ZX_OK) {
        return ZX_ERR_INTERNAL;
    }
    return usb_hci_configure_hub(&bus->hci, hub_id, speed, descriptor);
}

static zx_status_t bus_device_added(void* ctx, zx_device_t* hub_device, int port, usb_speed_t speed) {
    usb_bus_t* bus = ctx;
    uint32_t hub_id;
    if (usb_interface_get_device_id(hub_device, &hub_id) != ZX_OK) {
        return ZX_ERR_INTERNAL;
    }
    return usb_hci_hub_device_added(&bus->hci, hub_id, port, speed);
}

static zx_status_t bus_device_removed(void* ctx, zx_device_t* hub_device, int port) {
    usb_bus_t* bus = ctx;
    uint32_t hub_id;
    if (usb_interface_get_device_id(hub_device, &hub_id) != ZX_OK) {
        return ZX_ERR_INTERNAL;
    }
    return usb_hci_hub_device_removed(&bus->hci, hub_id, port);
}

static usb_bus_protocol_ops_t _bus_protocol = {
    .configure_hub = bus_configure_hub,
    .hub_device_added = bus_device_added,
    .hub_device_removed = bus_device_removed,
};

static void usb_bus_unbind(void* ctx) {
    zxlogf(INFO, "usb_bus_unbind\n");
    usb_bus_t* bus = ctx;
    usb_hci_set_bus_interface(&bus->hci, NULL);

    for (size_t i = 0; i < bus->max_device_count; i++) {
        usb_device_t* device = bus->devices[i];
        if (device) {
            device_remove(device->zxdev);
            bus->devices[i] = NULL;
        }
    }
    device_remove(bus->zxdev);
}

static void usb_bus_release(void* ctx) {
    zxlogf(INFO, "usb_bus_release\n");
    usb_bus_t* bus = ctx;
    free(bus->devices);
    free(bus);
}

static zx_protocol_device_t usb_bus_device_proto = {
    .version = DEVICE_OPS_VERSION,
    .unbind = usb_bus_unbind,
    .release = usb_bus_release,
};

static zx_status_t usb_bus_bind(void* ctx, zx_device_t* device, void** cookie) {
    usb_bus_t* bus = calloc(1, sizeof(usb_bus_t));
    if (!bus) {
        zxlogf(ERROR, "Not enough memory for usb_bus_t.\n");
        return ZX_ERR_NO_MEMORY;
    }

    if (device_get_protocol(device, ZX_PROTOCOL_USB_HCI, &bus->hci)) {
        free(bus);
        return ZX_ERR_NOT_SUPPORTED;
    }

    bus->hci_zxdev = device;
    bus->max_device_count = usb_hci_get_max_device_count(&bus->hci);
    bus->devices = calloc(bus->max_device_count, sizeof(usb_device_t *));
    if (!bus->devices) {
        zxlogf(ERROR, "Not enough memory for usb_bus_t->devices. max_device_count: %zu\n",
               bus->max_device_count);
        free(bus);
        return ZX_ERR_NO_MEMORY;
    }

    device_add_args_t args = {
        .version = DEVICE_ADD_ARGS_VERSION,
        .name = "usb",
        .ctx = bus,
        .ops = &usb_bus_device_proto,
        .proto_id = ZX_PROTOCOL_USB_BUS,
        .proto_ops = &_bus_protocol,
        .flags = DEVICE_ADD_NON_BINDABLE,
    };

    zx_status_t status = device_add(device, &args, &bus->zxdev);
    if (status == ZX_OK) {
        static usb_bus_interface_t bus_intf;
        bus_intf.ops = &_bus_interface;
        bus_intf.ctx = bus;
        usb_hci_set_bus_interface(&bus->hci, &bus_intf);
    } else {
        free(bus->devices);
        free(bus);
    }

    return status;
}

static zx_driver_ops_t usb_bus_driver_ops = {
    .version = DRIVER_OPS_VERSION,
    .bind = usb_bus_bind,
};

ZIRCON_DRIVER_BEGIN(usb_bus, usb_bus_driver_ops, "zircon", "0.1", 1)
    BI_MATCH_IF(EQ, BIND_PROTOCOL, ZX_PROTOCOL_USB_HCI),
ZIRCON_DRIVER_END(usb_bus)
