/*
 * VBAN SDK - compile-time configuration.
 *
 * Every option can be overridden with -D on the compiler command line or by
 * creating "vban_user_config.h" and defining VBAN_USER_CONFIG.
 *
 * The SDK core never calls malloc(). All objects are plain structs whose
 * worst-case size is fixed by the limits below, or take caller-provided
 * storage (jitter buffer ring, mixer matrix, reassembly buffers).
 */
#ifndef VBAN_CONFIG_H
#define VBAN_CONFIG_H

#ifdef VBAN_USER_CONFIG
#include "vban_user_config.h"
#endif

/* Max registered streams per receiver (vban_rx_t). ~64 bytes each. */
#ifndef VBAN_RX_MAX_STREAMS
#define VBAN_RX_MAX_STREAMS 8
#endif

/* Max destinations a single transmitter fans out to. 8 bytes each. */
#ifndef VBAN_TX_MAX_DEST
#define VBAN_TX_MAX_DEST 4
#endif

/* Max redundancy delay (packets) a transmitter can be configured with. */
#ifndef VBAN_TX_REDUNDANCY_MAX
#define VBAN_TX_REDUNDANCY_MAX 16
#endif

/* Max packets per recv/send batch (recvmmsg/sendmmsg on Linux). */
#ifndef VBAN_NET_BATCH
#define VBAN_NET_BATCH 16
#endif

/* Max replies per second the automatic PING0 responder sends (anti-amplification). */
#ifndef VBAN_PING_REPLY_RATE
#define VBAN_PING_REPLY_RATE 20
#endif

/* Of those, max replies per second to public (non-RFC1918) sources, so an
 * internet flood of spoofed pings cannot starve LAN discovery. */
#ifndef VBAN_PING_REPLY_RATE_PUBLIC
#define VBAN_PING_REPLY_RATE_PUBLIC 5
#endif

/* Min interval between two replies to the same source IP (ms). */
#ifndef VBAN_PING_PER_SOURCE_MS
#define VBAN_PING_PER_SOURCE_MS 100
#endif

/* Upper bound on the RT-Packet subscription timeout a client may request (s).
 * Voicemeeter clients ask for 15 s and refresh every 10 s. */
#ifndef VBAN_RTP_MAX_TIMEOUT_S
#define VBAN_RTP_MAX_TIMEOUT_S 30
#endif

/* Max RT-Packet subscriptions one source IP may hold. */
#ifndef VBAN_RTP_MAX_PER_IP
#define VBAN_RTP_MAX_PER_IP 2
#endif

/* Set to 0 to compile out the BSD-socket / Winsock layer (bring your own UDP).
 * Defaults to 0 on platforms without a known socket API (plain Arduino,
 * bare-metal), 1 elsewhere (Windows, Linux/Android, Apple, BSD, ESP-IDF, Zephyr). */
#ifndef VBAN_ENABLE_NET
#if defined(_WIN32) || defined(__unix__) || defined(__APPLE__) || defined(ESP_PLATFORM) || \
    defined(__ZEPHYR__) || defined(VBAN_FORCE_POSIX)
#define VBAN_ENABLE_NET 1
#else
#define VBAN_ENABLE_NET 0
#endif
#endif

/* Set to 0 to compile out float64 PCM support (saves code on small MCUs). */
#ifndef VBAN_ENABLE_F64
#define VBAN_ENABLE_F64 1
#endif

#endif /* VBAN_CONFIG_H */
