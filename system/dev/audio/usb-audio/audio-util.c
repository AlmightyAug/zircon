// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <driver/usb.h>
#include <stdlib.h>
#include <stdio.h>

#include "usb-audio.h"

uint32_t* usb_audio_parse_sample_rates(usb_audio_ac_format_type_i_desc* format_desc,
                                       int* out_count) {
    *out_count = 0;

    // sanity check the descriptor
    int count = format_desc->bSamFreqType;
    if (count == 0 || format_desc->bLength < sizeof(*format_desc) +
                                             (sizeof(format_desc->tSamFreq[0]) * count)) {
        printf("malformed format_desc in usb_audio_parse_sample_rates\n");
        return NULL;
    }
    uint32_t* result = (uint32_t *)malloc(count * sizeof(uint32_t));
    if (!result) return NULL;

    usb_audio_ac_samp_freq* ptr = format_desc->tSamFreq;
    for (int i = 0; i < count; i++) {
        uint32_t freq = ptr->freq[0] | (ptr->freq[1] << 8) | (ptr->freq[2] << 16);
        result[i] = freq;
        ptr++;
    }
    *out_count = count;
    return result;
}

zx_status_t usb_audio_set_sample_rate(usb_protocol_t* usb, uint8_t ep_addr, uint32_t sample_rate) {
    uint8_t buffer[3];
    buffer[0] = sample_rate;
    buffer[1] = sample_rate >> 8;
    buffer[2] = sample_rate >> 16;
    zx_status_t result = usb_control(usb, USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_ENDPOINT,
                                     USB_AUDIO_SET_CUR,
                                     USB_AUDIO_SAMPLING_FREQ_CONTROL << 8,
                                     ep_addr, &buffer, sizeof(buffer), ZX_TIME_INFINITE, NULL);
    return result;
}

// volume is in 0 - 100 range
zx_status_t usb_audio_set_volume(usb_protocol_t* usb, uint8_t interface_number, int fu_id,
                                 int volume) {
    uint16_t volume_min;
    uint16_t volume_max;
    zx_status_t status;
    size_t out_length;

    status = usb_control(usb, USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
                         USB_AUDIO_GET_MIN, USB_AUDIO_VOLUME_CONTROL << 8 | interface_number,
                         fu_id << 8, &volume_min, sizeof(volume_min), ZX_TIME_INFINITE,
                         &out_length);
    if (status != ZX_OK || out_length != sizeof(volume_min)) goto out;
    status = usb_control(usb, USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
                         USB_AUDIO_GET_MAX, USB_AUDIO_VOLUME_CONTROL << 8 | interface_number,
                         fu_id << 8, &volume_max, sizeof(volume_max), ZX_TIME_INFINITE,
                         &out_length);
    if (status != ZX_OK || status != sizeof(volume_min)) goto out;
    if (volume_min >= volume_max) return ZX_ERR_INTERNAL;

    // TODO (voydanoff) - maybe this should be logarithmic?
    uint16_t volume16 = volume_min + ((volume_max - volume_min) * volume) / 100;
    status = usb_control(usb, USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
                         USB_AUDIO_SET_CUR, USB_AUDIO_VOLUME_CONTROL << 8 | interface_number,
                         fu_id << 8, &volume16, sizeof(volume16), ZX_TIME_INFINITE, NULL);

out:
    if (status == ZX_ERR_IO_REFUSED) {
        // clear the stall
        usb_reset_endpoint(usb, 0);
    }
    return status;
}
