/*
 * netleashlim.sys: NetLeash's download limiter, a WFP callout driver.
 *
 * - At ALE_FLOW_ESTABLISHED every new non-loopback TCP or UDP flow gets a
 *   small context naming its program (a hash of its WFP app ID).
 * - TCP: at the STREAM layer, received data of a limited program is let
 *   through while its token bucket is positive and otherwise *deferred*.
 *   Deferred data stays in TCP's receive buffer, so the window closes and
 *   the sender slows down: no packets are dropped, copied or injected.
 *   A timer resumes deferred flows (FwpsStreamContinue0) as tokens come in.
 * - UDP (including QUIC): at DATAGRAM_DATA, received datagrams of a limited
 *   program over budget are dropped, and the sender's congestion control
 *   backs off.
 * - Uploads are not handled here: NetLeash uses Windows' built-in QoS.
 *
 * Narrow by design: the only command is "these programs may download at
 * these rates" (nlshared.h). Only SYSTEM and Administrators can open the
 * device, one handle at a time.
 *
 * Fails open twice over: the filters that route traffic here live in
 * NetLeash's dynamic WFP session (gone when the service stops), and closing
 * the device handle clears every limit and resumes every deferred flow.
 */
#include <ntddk.h>
#include <wdmsec.h>
#pragma warning(push)
#pragma warning(disable : 4201 4324) /* nameless unions, alignment padding in the network headers */
#include <ndis.h>
#include <fwpsk.h>
#pragma warning(pop)
#include "nlshared.h"
#include "nlbucket.h"

#define TAG 'mLlN'
#define TIMER_MS 5
#define RESUME_BATCH 64

static const GUID GUID_FLOW_V4 = NL_GUID_FLOW_V4;
static const GUID GUID_FLOW_V6 = NL_GUID_FLOW_V6;
static const GUID GUID_STREAM_V4 = NL_GUID_STREAM_V4;
static const GUID GUID_STREAM_V6 = NL_GUID_STREAM_V6;
static const GUID GUID_DGRAM_V4 = NL_GUID_DGRAM_V4;
static const GUID GUID_DGRAM_V6 = NL_GUID_DGRAM_V6;

enum { C_FLOW_V4, C_FLOW_V6, C_STREAM_V4, C_STREAM_V6, C_DGRAM_V4, C_DGRAM_V6, C_COUNT };

typedef struct NL_APP {
    UINT64 hash;
    NL_BUCKET bucket;
} NL_APP;

typedef struct NL_FLOW {
    LIST_ENTRY all;     /* g_flows */
    LIST_ENTRY pending; /* g_pending, while deferred */
    BOOLEAN isPending;
    BOOLEAN removing;   /* being removed at unload */
    UINT16 layerId;
    UINT32 calloutId;
    UINT64 flowId;
    UINT64 appHash;
} NL_FLOW;

typedef struct NL_RESUME {
    UINT64 flowId;
    UINT16 layerId;
    UINT32 calloutId;
} NL_RESUME;

static PDEVICE_OBJECT g_device;
static UINT32 g_calloutIds[C_COUNT];
static BOOLEAN g_registered[C_COUNT];
static BOOLEAN g_symlink;
static KSPIN_LOCK g_lock;       /* everything below */
static LIST_ENTRY g_flows;
static LIST_ENTRY g_pending;
static NL_APP g_apps[NL_MAX_LIMITS];
static ULONG g_appCount;
static BOOLEAN g_unloading;
static KTIMER g_timer;
static KDPC g_dpc;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD Unload;
_Dispatch_type_(IRP_MJ_CREATE) _Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH DispatchCreateClose;
_Dispatch_type_(IRP_MJ_CLEANUP) DRIVER_DISPATCH DispatchCleanup;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH DispatchIoctl;
KDEFERRED_ROUTINE TimerDpc;

/* Caller holds g_lock. */
static NL_APP *FindApp(UINT64 hash)
{
    ULONG i;
    for (i = 0; i < g_appCount; i++)
        if (g_apps[i].hash == hash)
            return &g_apps[i];
    return NULL;
}

/* ---- callouts ------------------------------------------------------------------- */

static NTSTATUS NTAPI Notify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID *filterKey, const FWPS_FILTER0 *filter)
{
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static void NTAPI FlowDelete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{
    NL_FLOW *f = (NL_FLOW *)(ULONG_PTR)flowContext;
    KLOCK_QUEUE_HANDLE lh;
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    if (f == NULL)
        return;
    KeAcquireInStackQueuedSpinLock(&g_lock, &lh);
    RemoveEntryList(&f->all);
    if (f->isPending)
        RemoveEntryList(&f->pending);
    KeReleaseInStackQueuedSpinLock(&lh);
    ExFreePoolWithTag(f, TAG);
}

/* Inspection only: remember which program a new flow belongs to. */
static void NTAPI FlowClassify(const FWPS_INCOMING_VALUES0 *in, const FWPS_INCOMING_METADATA_VALUES0 *meta,
                               void *layerData, const FWPS_FILTER0 *filter, UINT64 flowContext,
                               FWPS_CLASSIFY_OUT0 *out)
{
    BOOLEAN v4 = in->layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4;
    UINT appIdx = v4 ? FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_APP_ID : FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_APP_ID;
    UINT protoIdx = v4 ? FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL : FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL;
    UINT flagsIdx = v4 ? FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_FLAGS : FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_FLAGS;
    const FWP_BYTE_BLOB *app;
    UINT8 proto;
    UINT16 layerId;
    UINT32 calloutId;
    NL_FLOW *f;
    KLOCK_QUEUE_HANDLE lh;
    BOOLEAN stop;
    NTSTATUS st;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    out->actionType = FWP_ACTION_CONTINUE;

    if (!FWPS_IS_METADATA_FIELD_PRESENT(meta, FWPS_METADATA_FIELD_FLOW_HANDLE))
        return;
    if (in->incomingValue[flagsIdx].value.uint32 & FWP_CONDITION_FLAG_IS_LOOPBACK)
        return;
    app = in->incomingValue[appIdx].value.byteBlob;
    if (in->incomingValue[appIdx].value.type != FWP_BYTE_BLOB_TYPE || app == NULL || app->data == NULL || app->size == 0)
        return;
    proto = in->incomingValue[protoIdx].value.uint8;
    if (proto == 6) {
        layerId = v4 ? FWPS_LAYER_STREAM_V4 : FWPS_LAYER_STREAM_V6;
        calloutId = g_calloutIds[v4 ? C_STREAM_V4 : C_STREAM_V6];
    } else if (proto == 17) {
        layerId = v4 ? FWPS_LAYER_DATAGRAM_DATA_V4 : FWPS_LAYER_DATAGRAM_DATA_V6;
        calloutId = g_calloutIds[v4 ? C_DGRAM_V4 : C_DGRAM_V6];
    } else {
        return;
    }

    f = (NL_FLOW *)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(NL_FLOW), TAG);
    if (f == NULL)
        return; /* this flow simply goes unlimited */
    f->flowId = meta->flowHandle;
    f->layerId = layerId;
    f->calloutId = calloutId;
    f->appHash = nl_hash(app->data, app->size);

    KeAcquireInStackQueuedSpinLock(&g_lock, &lh);
    stop = g_unloading;
    if (!stop)
        InsertTailList(&g_flows, &f->all);
    KeReleaseInStackQueuedSpinLock(&lh);
    if (stop) {
        ExFreePoolWithTag(f, TAG);
        return;
    }

    st = FwpsFlowAssociateContext0(f->flowId, layerId, calloutId, (UINT64)(ULONG_PTR)f);
    if (!NT_SUCCESS(st)) {
        KeAcquireInStackQueuedSpinLock(&g_lock, &lh);
        RemoveEntryList(&f->all);
        KeReleaseInStackQueuedSpinLock(&lh);
        ExFreePoolWithTag(f, TAG);
    }
}

static void Permit(const FWPS_FILTER0 *filter, FWPS_CLASSIFY_OUT0 *out)
{
    out->actionType = FWP_ACTION_PERMIT;
    if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
        out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

/* TCP data: let it through while the program has budget, else defer it. */
static void NTAPI StreamClassify(const FWPS_INCOMING_VALUES0 *in, const FWPS_INCOMING_METADATA_VALUES0 *meta,
                                 void *layerData, const FWPS_FILTER0 *filter, UINT64 flowContext,
                                 FWPS_CLASSIFY_OUT0 *out)
{
    FWPS_STREAM_CALLOUT_IO_PACKET0 *io = (FWPS_STREAM_CALLOUT_IO_PACKET0 *)layerData;
    NL_FLOW *f = (NL_FLOW *)(ULONG_PTR)flowContext;
    KLOCK_QUEUE_HANDLE lh;
    NL_APP *a;
    UINT32 flags;
    BOOLEAN defer = FALSE;

    UNREFERENCED_PARAMETER(in);
    UNREFERENCED_PARAMETER(meta);
    if (!(out->rights & FWPS_RIGHT_ACTION_WRITE))
        return; /* someone with higher priority already decided */
    if (io == NULL || io->streamData == NULL || f == NULL) {
        Permit(filter, out);
        return;
    }
    io->streamAction = FWPS_STREAM_ACTION_NONE;
    io->countBytesRequired = 0;
    io->countBytesEnforced = 0;
    flags = io->streamData->flags;
    if (!(flags & FWPS_STREAM_FLAG_RECEIVE) ||
        (flags & (FWPS_STREAM_FLAG_RECEIVE_EXPEDITED | FWPS_STREAM_FLAG_RECEIVE_DISCONNECT |
                  FWPS_STREAM_FLAG_RECEIVE_ABORT))) {
        Permit(filter, out);
        return;
    }

    KeAcquireInStackQueuedSpinLock(&g_lock, &lh);
    a = FindApp(f->appHash);
    if (a != NULL && !f->removing && !nl_admit(&a->bucket, io->streamData->dataLength, KeQueryInterruptTime())) {
        if (!f->isPending) {
            InsertTailList(&g_pending, &f->pending);
            f->isPending = TRUE;
        }
        defer = TRUE;
    }
    KeReleaseInStackQueuedSpinLock(&lh);

    if (defer) {
        io->streamAction = FWPS_STREAM_ACTION_DEFER;
        out->actionType = FWP_ACTION_NONE;
    } else {
        Permit(filter, out);
    }
}

/* UDP: received datagrams over budget are dropped. */
static void NTAPI DatagramClassify(const FWPS_INCOMING_VALUES0 *in, const FWPS_INCOMING_METADATA_VALUES0 *meta,
                                   void *layerData, const FWPS_FILTER0 *filter, UINT64 flowContext,
                                   FWPS_CLASSIFY_OUT0 *out)
{
    NET_BUFFER_LIST *nbl = (NET_BUFFER_LIST *)layerData;
    NL_FLOW *f = (NL_FLOW *)(ULONG_PTR)flowContext;
    UINT dirIdx = in->layerId == FWPS_LAYER_DATAGRAM_DATA_V4 ? FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION
                                                             : FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION;
    KLOCK_QUEUE_HANDLE lh;
    NL_APP *a;
    ULONG bytes;
    BOOLEAN drop = FALSE;

    UNREFERENCED_PARAMETER(meta);
    if (!(out->rights & FWPS_RIGHT_ACTION_WRITE))
        return;
    if (f == NULL || nbl == NULL || NET_BUFFER_LIST_FIRST_NB(nbl) == NULL ||
        in->incomingValue[dirIdx].value.uint32 != FWP_DIRECTION_INBOUND) {
        Permit(filter, out);
        return;
    }
    bytes = NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(nbl));

    KeAcquireInStackQueuedSpinLock(&g_lock, &lh);
    a = FindApp(f->appHash);
    if (a != NULL && !nl_admit(&a->bucket, bytes, KeQueryInterruptTime()))
        drop = TRUE;
    KeReleaseInStackQueuedSpinLock(&lh);

    if (drop) {
        out->actionType = FWP_ACTION_BLOCK;
        out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB; /* drop silently, no ICMP */
    } else {
        Permit(filter, out);
    }
}

/* ---- resuming deferred flows ------------------------------------------------------ */

/* Take flows that may continue off the pending list; `all`: every one of them. */
static ULONG CollectResumable(NL_RESUME *batch, BOOLEAN all)
{
    KLOCK_QUEUE_HANDLE lh;
    LIST_ENTRY *e, *next;
    ULONG n = 0;
    UINT64 now = KeQueryInterruptTime();

    KeAcquireInStackQueuedSpinLock(&g_lock, &lh);
    for (e = g_pending.Flink; e != &g_pending && n < RESUME_BATCH; e = next) {
        NL_FLOW *f = CONTAINING_RECORD(e, NL_FLOW, pending);
        NL_APP *a = FindApp(f->appHash);
        next = e->Flink;
        if (!all && a != NULL) {
            nl_refill(&a->bucket, now);
            if (a->bucket.tokens <= 0)
                continue;
        }
        RemoveEntryList(&f->pending);
        f->isPending = FALSE;
        batch[n].flowId = f->flowId;
        batch[n].layerId = f->layerId;
        batch[n].calloutId = f->calloutId;
        n++;
    }
    KeReleaseInStackQueuedSpinLock(&lh);
    return n;
}

/* Never called with g_lock held: continuing re-classifies the flow at once. */
static ULONG Resume(BOOLEAN all)
{
    NL_RESUME batch[RESUME_BATCH];
    ULONG n = CollectResumable(batch, all), i;
    for (i = 0; i < n; i++)
        FwpsStreamContinue0(batch[i].flowId, batch[i].calloutId, batch[i].layerId, FWPS_STREAM_FLAG_RECEIVE);
    return n;
}

static void ResumeAll(void)
{
    /* With no limits left nothing gets deferred again, so this ends. */
    while (Resume(TRUE) == RESUME_BATCH) {
    }
}

void TimerDpc(PKDPC dpc, PVOID ctx, PVOID a1, PVOID a2)
{
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(a1);
    UNREFERENCED_PARAMETER(a2);
    Resume(FALSE);
}

/* ---- device ----------------------------------------------------------------------- */

static void ClearLimits(void)
{
    KLOCK_QUEUE_HANDLE lh;
    KeAcquireInStackQueuedSpinLock(&g_lock, &lh);
    g_appCount = 0;
    KeReleaseInStackQueuedSpinLock(&lh);
    ResumeAll();
}

static NTSTATUS SetLimits(const void *buf, ULONG len)
{
    const NL_SET_LIMITS *req = (const NL_SET_LIMITS *)buf;
    static NL_APP fresh[NL_MAX_LIMITS]; /* only touched under g_lock */
    KLOCK_QUEUE_HANDLE lh;
    ULONG i, n;
    UINT64 now = KeQueryInterruptTime();

    if (buf == NULL || len < NL_SET_LIMITS_HEADER)
        return STATUS_INVALID_PARAMETER;
    if (req->version != NL_PROTOCOL_VERSION)
        return STATUS_REVISION_MISMATCH;
    n = req->count;
    if (n > NL_MAX_LIMITS || len != NL_SET_LIMITS_HEADER + n * sizeof(NL_LIMIT))
        return STATUS_INVALID_PARAMETER;
    for (i = 0; i < n; i++)
        if (req->entries[i].down_rate == 0)
            return STATUS_INVALID_PARAMETER;

    KeAcquireInStackQueuedSpinLock(&g_lock, &lh);
    for (i = 0; i < n; i++) {
        /* A program that keeps its limit keeps its balance. */
        NL_APP *old = FindApp(req->entries[i].app_hash);
        fresh[i].hash = req->entries[i].app_hash;
        if (old != NULL) {
            fresh[i].bucket = old->bucket;
            fresh[i].bucket.rate = req->entries[i].down_rate;
        } else {
            nl_bucket_init(&fresh[i].bucket, req->entries[i].down_rate, now);
        }
    }
    RtlCopyMemory(g_apps, fresh, n * sizeof(NL_APP));
    g_appCount = n;
    KeReleaseInStackQueuedSpinLock(&lh);
    Resume(FALSE); /* programs that lost their limit continue at the next tick at the latest */
    return STATUS_SUCCESS;
}

static NTSTATUS Complete(PIRP irp, NTSTATUS st, ULONG_PTR info)
{
    irp->IoStatus.Status = st;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    return Complete(irp, STATUS_SUCCESS, 0);
}

/* The service closed its handle, or died: lift every limit. */
NTSTATUS DispatchCleanup(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    ClearLimits();
    return Complete(irp, STATUS_SUCCESS, 0);
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION s = IoGetCurrentIrpStackLocation(irp);
    ULONG code = s->Parameters.DeviceIoControl.IoControlCode;
    void *buf = irp->AssociatedIrp.SystemBuffer;
    UNREFERENCED_PARAMETER(dev);

    switch (code) {
    case NL_IOCTL_GET_VERSION:
        if (buf == NULL || s->Parameters.DeviceIoControl.OutputBufferLength < sizeof(UINT32))
            return Complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
        *(UINT32 *)buf = NL_PROTOCOL_VERSION;
        return Complete(irp, STATUS_SUCCESS, sizeof(UINT32));
    case NL_IOCTL_SET_LIMITS:
        return Complete(irp, SetLimits(buf, s->Parameters.DeviceIoControl.InputBufferLength), 0);
    default:
        return Complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
}

/* ---- load / unload ---------------------------------------------------------------- */

static NTSTATUS RegisterCallout(int i, const GUID *key, FWPS_CALLOUT_CLASSIFY_FN0 fn, UINT32 flags)
{
    FWPS_CALLOUT0 c;
    NTSTATUS st;
    RtlZeroMemory(&c, sizeof(c));
    c.calloutKey = *key;
    c.flags = flags;
    c.classifyFn = fn;
    c.notifyFn = Notify;
    c.flowDeleteFn = FlowDelete;
    st = FwpsCalloutRegister0(g_device, &c, &g_calloutIds[i]);
    if (NT_SUCCESS(st))
        g_registered[i] = TRUE;
    return st;
}

/* Detach our context from every flow (WFP calls FlowDelete for each). */
static void RemoveAllFlowContexts(void)
{
    for (;;) {
        KLOCK_QUEUE_HANDLE lh;
        LIST_ENTRY *e;
        NL_FLOW *f = NULL;
        NL_RESUME r = {0};
        KeAcquireInStackQueuedSpinLock(&g_lock, &lh);
        for (e = g_flows.Flink; e != &g_flows; e = e->Flink) {
            NL_FLOW *c = CONTAINING_RECORD(e, NL_FLOW, all);
            if (!c->removing) {
                f = c;
                break;
            }
        }
        if (f != NULL) {
            f->removing = TRUE;
            r.flowId = f->flowId;
            r.layerId = f->layerId;
            r.calloutId = f->calloutId;
        }
        KeReleaseInStackQueuedSpinLock(&lh);
        if (f == NULL)
            break;
        /* On failure the flow is already being deleted; FlowDelete still comes. */
        FwpsFlowRemoveContext0(r.flowId, r.layerId, r.calloutId);
    }
}

static void Teardown(void)
{
    KLOCK_QUEUE_HANDLE lh;
    LARGE_INTEGER wait;
    int i, tries;

    KeAcquireInStackQueuedSpinLock(&g_lock, &lh);
    g_unloading = TRUE;
    g_appCount = 0;
    KeReleaseInStackQueuedSpinLock(&lh);

    KeCancelTimer(&g_timer);
    KeFlushQueuedDpcs();
    ResumeAll();
    RemoveAllFlowContexts();

    wait.QuadPart = -10 * 1000 * 100; /* 100 ms */
    for (i = 0; i < C_COUNT; i++) {
        if (!g_registered[i])
            continue;
        /* Busy while a flow still holds a context; those are being deleted. */
        for (tries = 0; tries < 50; tries++) {
            if (FwpsCalloutUnregisterById0(g_calloutIds[i]) != STATUS_DEVICE_BUSY)
                break;
            KeDelayExecutionThread(KernelMode, FALSE, &wait);
        }
        g_registered[i] = FALSE;
    }
    if (g_symlink) {
        UNICODE_STRING link = RTL_CONSTANT_STRING(NL_DOS_NAME);
        IoDeleteSymbolicLink(&link);
        g_symlink = FALSE;
    }
    if (g_device != NULL) {
        IoDeleteDevice(g_device);
        g_device = NULL;
    }
}

void Unload(PDRIVER_OBJECT drv)
{
    UNREFERENCED_PARAMETER(drv);
    Teardown();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(NL_DEVICE_NAME);
    UNICODE_STRING link = RTL_CONSTANT_STRING(NL_DOS_NAME);
    /* SYSTEM and Administrators only. */
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    /* {4e4c00ff-7a1e-4c1b-9b52-316e65746cff}: the device's class, for its security */
    static const GUID devClass = {0x4e4c00ff, 0x7a1e, 0x4c1b, {0x9b, 0x52, 0x31, 0x6e, 0x65, 0x74, 0x6c, 0xff}};
    LARGE_INTEGER due;
    NTSTATUS st;
    UNREFERENCED_PARAMETER(reg);

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    KeInitializeSpinLock(&g_lock);
    InitializeListHead(&g_flows);
    InitializeListHead(&g_pending);
    KeInitializeTimer(&g_timer);
    KeInitializeDpc(&g_dpc, TimerDpc, NULL);

    drv->DriverUnload = Unload;
    drv->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    drv->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    drv->MajorFunction[IRP_MJ_CLEANUP] = DispatchCleanup;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    /* Exclusive: one handle at a time, the NetLeash service's. */
    st = IoCreateDeviceSecure(drv, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &sddl,
                              &devClass, &g_device);
    if (!NT_SUCCESS(st))
        return st;
    st = IoCreateSymbolicLink(&link, &name);
    if (!NT_SUCCESS(st))
        goto fail;
    g_symlink = TRUE;

    st = RegisterCallout(C_FLOW_V4, &GUID_FLOW_V4, FlowClassify, 0);
    if (NT_SUCCESS(st))
        st = RegisterCallout(C_FLOW_V6, &GUID_FLOW_V6, FlowClassify, 0);
    if (NT_SUCCESS(st))
        st = RegisterCallout(C_STREAM_V4, &GUID_STREAM_V4, StreamClassify, FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW);
    if (NT_SUCCESS(st))
        st = RegisterCallout(C_STREAM_V6, &GUID_STREAM_V6, StreamClassify, FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW);
    if (NT_SUCCESS(st))
        st = RegisterCallout(C_DGRAM_V4, &GUID_DGRAM_V4, DatagramClassify, FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW);
    if (NT_SUCCESS(st))
        st = RegisterCallout(C_DGRAM_V6, &GUID_DGRAM_V6, DatagramClassify, FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW);
    if (!NT_SUCCESS(st))
        goto fail;

    due.QuadPart = -10 * 1000 * TIMER_MS;
    KeSetTimerEx(&g_timer, due, TIMER_MS, &g_dpc);
    return STATUS_SUCCESS;

fail:
    Teardown();
    return st;
}
