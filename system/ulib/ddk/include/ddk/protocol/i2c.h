// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <zircon/compiler.h>
#include <zircon/types.h>

__BEGIN_CDECLS;

// Protocol for an i2c channel
typedef struct {
    zx_status_t (*read)(void* ctx, void* read_buf, size_t read_buf_length, zx_time_t timeout,
                        size_t* actual);
    zx_status_t (*write)(void* ctx, const void* write_buf, size_t write_buf_length);
    zx_status_t (*write_async)(void* ctx, const void* write_buf, size_t write_buf_length);
    zx_status_t (*flush)(void* ctx, zx_time_t timeout);
    zx_status_t (*write_read)(void* ctx, const void* writebuf, size_t write_buf_length,
                              void* read_buf, size_t read_buf_len, zx_time_t timeout, size_t* actual);
    zx_status_t (*set_bitrate)(void* ctx, uint32_t bitrate);
} i2c_channel_ops_t;

typedef struct {
    i2c_channel_ops_t* ops;
    void* ctx;
} i2c_channel_t;

// Reads data from the i2c channel.
// Returns ZX_ERR_TIMED_OUT if timeout is reached before data arrives.
// If successful, the actual number of bytes read are returned in "actual".
// Returns ZX_ERR_BUFFER_TOO_SMALL if buffer is not large enough to hold received data packet.
static inline zx_status_t i2c_read(i2c_channel_t* channel, void* read_buf, size_t read_buf_length,
                                   zx_time_t timeout, size_t* actual) {
    return channel->ops->read(channel->ctx, read_buf, read_buf_length, timeout, actual);
}

// Writes data to the i2c channel. Does not return until write operation is complete.
static inline zx_status_t i2c_write(i2c_channel_t* channel, const void* write_buf,
                                    size_t write_buf_length) {
    return channel->ops->write(channel->ctx, write_buf, write_buf_length);
}

// Writes data to the i2c channel. May return before the write operation is completed.
static inline zx_status_t i2c_write_async(i2c_channel_t* channel, const void* write_buf,
                                          size_t write_buf_length) {
    return channel->ops->write_async(channel->ctx, write_buf, write_buf_length);
}

// Blocks until all pending write_async operations have completed or timeout has reached.
// If any of the pending write_async fail, the error code for the write will be returned here
// and any remaining write_async operations will be cancelled.
static inline zx_status_t i2c_flush(i2c_channel_t* channel, zx_time_t timeout) {
    return channel->ops->flush(channel->ctx, timeout);
}

// Performs an i2c write followed by an i2c read.
// It is safe to use the same buffer for write_buf and read_buf.
static inline zx_status_t i2c_write_read(i2c_channel_t* channel, const void* write_buf,
                                         size_t write_buf_length, void* read_buf,
                                         size_t read_buf_len, zx_time_t timeout, size_t* actual) {
    return channel->ops->write_read(channel->ctx, write_buf, write_buf_length, read_buf,
                                    read_buf_len, timeout, actual);
}

// Sets the bitrate for the i2c channel
static inline zx_status_t i2c_set_bitrate(i2c_channel_t* channel, uint32_t bitrate) {
    return channel->ops->set_bitrate(channel->ctx, bitrate);
}

// Protocol for i2c
typedef struct {
    zx_status_t (*get_channel)(void* ctx, uint32_t channel_id, i2c_channel_t* channel);
    zx_status_t (*get_channel_by_address)(void* ctx, uint32_t bus_id, uint16_t address,
                                          i2c_channel_t* channel);
    void (*channel_release)(void* ctx, i2c_channel_t* channel);
} i2c_protocol_ops_t;

typedef struct {
    i2c_protocol_ops_t* ops;
    void* ctx;
} i2c_protocol_t;

// Returns an i2c channel protocol based on an abstract channel ID.
// Intended for generic drivers that do not know the details
//  of the platform they are running on.
static inline zx_status_t i2c_get_channel(i2c_protocol_t* i2c, uint32_t channel_id,
                                          i2c_channel_t* channel) {
    return i2c->ops->get_channel(i2c->ctx, channel_id, channel);
}

// Returns an i2c channel protocol based on a bus ID and address.
// Addresses with the high 4 bits set (0xF000) are treated as 10-bit addresses.
// Otherwise the address is treated as 7-bit.
// This is intended for platform-specific drivers that know the details
// of the platform they are running on.
static inline zx_status_t i2c_get_channel_by_address(i2c_protocol_t* i2c, uint32_t bus_id,
                                                     uint16_t address, i2c_channel_t* channel) {
    return i2c->ops->get_channel_by_address(i2c->ctx, bus_id, address, channel);
}

// releases any resources owned by the i2c channel
static inline void i2c_channel_release(i2c_protocol_t* i2c, i2c_channel_t* channel) {
    i2c->ops->channel_release(i2c->ctx, channel);
}

__END_CDECLS;
