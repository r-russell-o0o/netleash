/*
 * NetLeash limiter: what the driver and NetLeash's service share.
 * src/kdriver.rs mirrors these numbers; keep them in step.
 *
 * The device accepts exactly one command that changes anything: "these
 * programs may download at these rates". It cannot read, change or inject
 * packets for anyone, which is what sets it apart from a general-purpose
 * packet driver such as WinDivert.
 */
#pragma once

#define NL_DEVICE_NAME  L"\\Device\\NetLeashLimiter"
#define NL_DOS_NAME     L"\\DosDevices\\NetLeashLimiter"   /* \\.\NetLeashLimiter */

#define NL_PROTOCOL_VERSION 1u
#define NL_MAX_LIMITS 256u

/* CTL_CODE(0x8E4C, fn, METHOD_BUFFERED, access) */
#define NL_DEVICE_TYPE 0x8E4Cu
#define NL_CTL(fn, access) ((NL_DEVICE_TYPE << 16) | ((access) << 14) | ((fn) << 2) | 0u)
/* out: UINT32 protocol version */
#define NL_IOCTL_GET_VERSION NL_CTL(0x800u, 1u) /* FILE_READ_ACCESS  = 0x8E4C6000 */
/* in: NL_SET_LIMITS; replaces all limits */
#define NL_IOCTL_SET_LIMITS  NL_CTL(0x801u, 2u) /* FILE_WRITE_ACCESS = 0x8E4CA004 */

#pragma pack(push, 1)
typedef struct NL_LIMIT {
    /* FNV-1a 64 of the program's WFP app ID blob (FwpmGetAppIdFromFileName0) */
    unsigned long long app_hash;
    /* download limit, bytes per second (> 0) */
    unsigned long long down_rate;
} NL_LIMIT;

typedef struct NL_SET_LIMITS {
    unsigned int version; /* NL_PROTOCOL_VERSION */
    unsigned int count;   /* <= NL_MAX_LIMITS; entries follow */
    NL_LIMIT entries[1];
} NL_SET_LIMITS;
#pragma pack(pop)

#define NL_SET_LIMITS_HEADER 8u

/*
 * WFP callout keys. The driver registers the callouts; NetLeash's service
 * adds the matching callout objects and filters in its own dynamic WFP
 * session, so they vanish when the service stops and the driver goes idle.
 */
#define NL_GUID_FLOW_V4 {0x4e4c0001, 0x7a1e, 0x4c1b, {0x9b, 0x52, 0x31, 0x6e, 0x65, 0x74, 0x6c, 0x01}}
#define NL_GUID_FLOW_V6 {0x4e4c0002, 0x7a1e, 0x4c1b, {0x9b, 0x52, 0x31, 0x6e, 0x65, 0x74, 0x6c, 0x02}}
#define NL_GUID_STREAM_V4 {0x4e4c0003, 0x7a1e, 0x4c1b, {0x9b, 0x52, 0x31, 0x6e, 0x65, 0x74, 0x6c, 0x03}}
#define NL_GUID_STREAM_V6 {0x4e4c0004, 0x7a1e, 0x4c1b, {0x9b, 0x52, 0x31, 0x6e, 0x65, 0x74, 0x6c, 0x04}}
#define NL_GUID_DGRAM_V4 {0x4e4c0005, 0x7a1e, 0x4c1b, {0x9b, 0x52, 0x31, 0x6e, 0x65, 0x74, 0x6c, 0x05}}
#define NL_GUID_DGRAM_V6 {0x4e4c0006, 0x7a1e, 0x4c1b, {0x9b, 0x52, 0x31, 0x6e, 0x65, 0x74, 0x6c, 0x06}}
