#-                                                                                                                                                                                                                                                                                                                [218/1103]# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2021 Hesham Almatary
#
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory (Department of Computer Science and
# Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
# DARPA SSITH research programme.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#


def configure(ctx):
    print("Configuring coreMQTT-Agent Demo @", ctx.path.abspath())

    ctx.env.append_value(
        'INCLUDES',
        [
            ctx.path.abspath() + "/source/configuration-files/",
            ctx.path.abspath() + "/lib/FreeRTOS/utilities/logging/",
            ctx.path.abspath() + "/lib/FreeRTOS/freertos-plus-mqtt/",
            ctx.path.abspath() + "/lib/FreeRTOS/utilities/exponential_backoff/",
            ctx.path.abspath() + "/lib/FreeRTOS/utilities/crypto/include",
            ctx.path.abspath() + '/lib/FreeRTOS/utilities/mbedtls_freertos/',
            ctx.path.abspath() + '/lib/AWS/ota-pal/freertos/',
        ])

    ctx.env.append_value('DEFINES', [
        'configPROG_ENTRY     = main',
        'MBEDTLS_CONFIG_FILE  = "mbedtls_config.h"'
    ])

    ctx.define('configUSE_NET_VIRTIO', 1)
    ctx.define('mainCONFIG_INIT_FAT_FILESYSTEM', 1)
    ctx.define('_STAT_H_', 1)
    ctx.define('configCOMPARTMENTS_NUM', 0)
    ctx.define('configMAXLEN_COMPNAME', 255)

    ctx.env.append_value('LIB_DEPS', [
        'freertos_tcpip', 'virtio', 'freertos_libota', 'freertos_libcorejson',
        'freertos_fat', 'freertos_libcoremqtt', 'freertos_libmbedtls',
        'freertos_libnetwork_transport', 'libtinycbor'
    ])


def build(bld):
    name = "aws_ota"
    print("Building coreMQTT-Agent OTA Demo")

    cflags = []

    if bld.env.COMPARTMENTALIZE:
        cflags = ['-cheri-cap-table-abi=gprel']

    bld.stlib(
        features=['c'],
        cflags=bld.env.CFLAGS + cflags,
        source=[
            'source/main.c',
            'source/connection_manager.c',
            'source/large_message_sub_pub_demo.c',
            'source/ota_over_mqtt_demo.c',
            'source/simple_sub_pub_demo.c',
            'lib/FreeRTOS/freertos-plus-mqtt/freertos_mqtt_agent.c',

            'lib/FreeRTOS/utilities/crypto/src/iot_crypto.c',
            'lib/FreeRTOS/utilities/exponential_backoff/exponential_backoff.c',
            'lib/AWS/ota-pal/freertos/ota_pal.c',
        ],
        use=[
            "freertos_core_headers", "freertos_bsp_headers",
            "freertos_tcpip_headers", "virtio_headers",
            'freertos_libota_headers', 'freertos_libcorejson_headers',
            'freertos_fat_headers', 'libtinycbor_headers',
            'freertos_libcoremqtt_headers', 'freertos_libmbedtls_headers',
            'freertos_libnetwork_transport_headers'
        ],
        target=name)
