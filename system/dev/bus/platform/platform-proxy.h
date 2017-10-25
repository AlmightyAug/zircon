// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <stdint.h>
#include <ddk/device.h>
#include <ddk/protocol/gpio.h>
#include <ddk/protocol/i2c.h>
#include <ddk/protocol/usb-mode-switch.h>

// RPC ops
enum {
    // ZX_PROTOCOL_PLATFORM_DEV
    PDEV_GET_MMIO = 1,
    PDEV_GET_INTERRUPT,

    // ZX_PROTOCOL_USB_MODE_SWITCH
    PDEV_UMS_GET_INITIAL_MODE,
    PDEV_UMS_SET_MODE,

    // ZX_PROTOCOL_GPIO
    PDEV_GPIO_CONFIG,
    PDEV_GPIO_READ,
    PDEV_GPIO_WRITE,

    // ZX_PROTOCOL_I2C
    PDEV_I2C_GET_CHANNEL,
    PDEV_I2C_GET_CHANNEL_BY_ADDRESS,
    PDEV_I2C_CHANNEL_RELEASE,
    PDEV_I2C_READ,
    PDEV_I2C_WRITE,
    PDEV_I2C_WRITE_ASYNC,
    PDEV_I2C_FLUSH,
    PDEV_I2C_WRITE_READ,
    PDEV_I2C_SET_BITRATE,
};

typedef struct {
//    uintptr_t client_ref;
    void* server_ctx;
    uint32_t id;    // channel ID or bus ID
    uint16_t address;
    zx_time_t timeout;
    uint32_t bitrate;
} pdev_i2c_req_t;

typedef struct {
//    uintptr_t client_ref;
    void* server_ctx;

    size_t actual;
} pdev_i2c_resp_t;

typedef struct {
    zx_txid_t txid;
    uint32_t op;
    uint32_t index;
    union {
        usb_mode_t usb_mode;
        gpio_config_flags_t gpio_flags;
        uint8_t gpio_value;
        pdev_i2c_req_t i2c;
    };
} pdev_req_t;

typedef struct {
    zx_txid_t txid;
    zx_status_t status;
    union {
        usb_mode_t usb_mode;
        uint8_t gpio_value;
        pdev_i2c_resp_t i2c;
    };
} pdev_resp_t;
