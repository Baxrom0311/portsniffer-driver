//
// PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
// Copyright 2020-2022 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
//
// SPDX-License-Identifier: MIT
//

#include "EnlyzePortSniffer.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, PortSnifferControlCreate)
#pragma alloc_text (PAGE, PortSnifferControlEvtIoDeviceControl)
#pragma alloc_text (PAGE, PortSnifferControlGetAttachedPorts)
#pragma alloc_text (PAGE, PortSnifferControlGetVersion)
#pragma alloc_text (PAGE, PortSnifferControlPopPortLogEntry)
#pragma alloc_text (PAGE, PortSnifferControlPopPortLogEntryInternal)
#pragma alloc_text (PAGE, PortSnifferControlResetPortMonitoring)
#pragma alloc_text (PAGE, PortSnifferFilterAddPortLogEntry)
#pragma alloc_text (PAGE, PortSnifferFilterClearPortLog)
#pragma alloc_text (PAGE, PortSnifferFilterEvtDeviceAdd)
#pragma alloc_text (PAGE, PortSnifferFilterEvtDeviceCleanup)
#pragma alloc_text (PAGE, PortSnifferFilterEvtIoDeviceControl)
#pragma alloc_text (PAGE, PortSnifferFilterEvtIoDeviceControlInternal)
#pragma alloc_text (PAGE, PortSnifferFilterEvtIoRead)
#pragma alloc_text (PAGE, PortSnifferFilterEvtReadLogQueueIoRead)
#pragma alloc_text (PAGE, PortSnifferFilterEvtIoWrite)
#endif

WDFDEVICE ControlDevice = NULL;
WDFCOLLECTION FilterDevices = NULL;
WDFWAITLOCK FilterDevicesLock = NULL;
WDFLOOKASIDE PortLogLookaside = NULL;


__drv_functionClass(DRIVER_INITIALIZE)
__drv_sameIRQL
NTSTATUS
DriverEntry(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;

    WDFDRIVER driver;

    KdPrint(("ENLYZE PortSniffer Driver " PORTSNIFFER_VERSION_COMBINED "\n"));

    // Create our driver object.
    WDF_DRIVER_CONFIG_INIT(&config, PortSnifferFilterEvtDeviceAdd);
    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfDriverCreate failed, status = 0x%08lX\n", status));
        return status;
    }

    // Maintain a collection of all active port filter devices.
    // This MUST be created before the control device, otherwise an IOCTL that
    // arrives between PortSnifferControlCreate and WdfWaitLockCreate would
    // dereference a NULL FilterDevicesLock.
    status = WdfCollectionCreate(WDF_NO_OBJECT_ATTRIBUTES, &FilterDevices);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfCollectionCreate failed, status = 0x%08lX\n", status));
        return status;
    }

    // Guard accesses to that collection.
    status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &FilterDevicesLock);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfWaitLockCreate failed, status = 0x%08lX\n", status));
        return status;
    }

    // Create a lookaside list to serve all memory requests for port log entries.
    status = WdfLookasideListCreate(WDF_NO_OBJECT_ATTRIBUTES,
        sizeof(PORTLOG_ENTRY) + PORTSNIFFER_PORTLOG_ENTRY_LENGTH,
        PagedPool,
        WDF_NO_OBJECT_ATTRIBUTES,
        POOL_TAG,
        &PortLogLookaside);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfLookasideListCreate failed, status = 0x%08lX\n", status));
        return status;
    }

    // Create our control device once all global state is ready. The control
    // device persists for the lifetime of the driver in the multi-port variant.
    status = PortSnifferControlCreate(driver);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("PortSnifferControlCreate failed, status = 0x%08lX\n", status));
        return status;
    }

    return STATUS_SUCCESS;
}

__drv_requiresIRQL(PASSIVE_LEVEL)
NTSTATUS
PortSnifferControlCreate(
    __in WDFDRIVER Driver
    )
{
    DECLARE_CONST_UNICODE_STRING(ntDeviceName, CONTROL_DEVICE_NAME_STRING);
    DECLARE_CONST_UNICODE_STRING(symbolicLinkName, CONTROL_SYMBOLIC_LINK_NAME_STRING);

    WDFDEVICE controlDevice = NULL;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    PWDFDEVICE_INIT deviceInit = NULL;
    WDF_OBJECT_ATTRIBUTES ioQueueAttributes;
    WDF_IO_QUEUE_CONFIG ioQueueConfig;
    NTSTATUS status;

    PAGED_CODE();
    KdPrint(("PortSnifferControlCreate(%p)\n", Driver));

    // Allocate a WDFDEVICE_INIT structure for creating an administrator-only control device.
    deviceInit = WdfControlDeviceInitAllocate(Driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (deviceInit == NULL)
    {
        KdPrint(("WdfControlDeviceInitAllocate failed\n"));
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    // Set the control device name.
    status = WdfDeviceInitAssignName(deviceInit, &ntDeviceName);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfDeviceInitAssignName failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // The control device is intentionally NOT exclusive: the PortSniffer-Tool
    // monitoring path opens two handles (synchronous + overlapped) so it can
    // both park a pop request and issue control IOCTLs in parallel. The new
    // pending-pop design protects against same-port concurrency via a
    // per-FilterContext PendingPopRequest slot.

    // Create our control device.
    WDF_OBJECT_ATTRIBUTES_INIT(&deviceAttributes);
    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &controlDevice);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfDeviceCreate failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Register a callback for the application's DeviceIoControl calls to our control device.
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchSequential);
    ioQueueConfig.EvtIoDeviceControl = PortSnifferControlEvtIoDeviceControl;

    // Ensure that all callback routines are run at IRQL == PASSIVE_LEVEL as we are acquiring a wait lock there.
    WDF_OBJECT_ATTRIBUTES_INIT(&ioQueueAttributes);
    ioQueueAttributes.ExecutionLevel = WdfExecutionLevelPassive;

    // Set up an I/O Queue to handle requests to our control device.
    status = WdfIoQueueCreate(controlDevice, &ioQueueConfig, &ioQueueAttributes, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfIoQueueCreate failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Create a symbolic link to our control device for the application.
    status = WdfDeviceCreateSymbolicLink(controlDevice, &symbolicLinkName);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfDeviceCreateSymbolicLink failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Finish up and prevent controlDevice from being freed in the Cleanup step.
    WdfControlFinishInitializing(controlDevice);
    ControlDevice = controlDevice;
    controlDevice = NULL;
    status = STATUS_SUCCESS;

Cleanup:
    if (controlDevice)
    {
        WdfObjectDelete(controlDevice);
    }

    if (deviceInit)
    {
        WdfDeviceInitFree(deviceInit);
    }

    return status;
}

__drv_functionClass(EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL)
__drv_sameIRQL
__drv_maxIRQL(DISPATCH_LEVEL)
void
PortSnifferControlEvtIoDeviceControl(
    __in WDFQUEUE Queue,
    __in WDFREQUEST Request,
    __in size_t OutputBufferLength,
    __in size_t InputBufferLength,
    __in ULONG IoControlCode
    )
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    PAGED_CODE();
    KdPrint(("PortSnifferControlEvtIoDeviceControl(%p, %p, %Iu, %Iu, %lu)\n", Queue, Request, OutputBufferLength, InputBufferLength, IoControlCode));

    switch (IoControlCode)
    {
        case PORTSNIFFER_IOCTL_CONTROL_GET_VERSION:
            PortSnifferControlGetVersion(Request);
            break;

        case PORTSNIFFER_IOCTL_CONTROL_GET_ATTACHED_PORTS:
            PortSnifferControlGetAttachedPorts(Request);
            break;

        case PORTSNIFFER_IOCTL_CONTROL_RESET_PORT_MONITORING:
            PortSnifferControlResetPortMonitoring(Request);
            break;

        case PORTSNIFFER_IOCTL_CONTROL_POP_PORTLOG_ENTRY:
            PortSnifferControlPopPortLogEntry(Request);
            break;

        default:
            WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
            break;
    }
}

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferControlGetAttachedPorts(
    __in WDFREQUEST Request
    )
{
    ULONG count;
    WDFDEVICE device;
    ULONG i;
    PWSTR p;
    PFILTER_CONTEXT filterContext;
    PPORTSNIFFER_GET_ATTACHED_PORTS_RESPONSE response;
    size_t responseBufferLength;
    NTSTATUS status;

    PAGED_CODE();
    KdPrint(("PortSnifferControlGetAttachedPorts(%p)\n", Request));

    // Get the output buffer that must have enough space for at least the Length field.
    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(ULONG), &response, &responseBufferLength);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfRequestRetrieveOutputBuffer failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
        return;
    }

    // Calculate the required output buffer size.
    WdfWaitLockAcquire(FilterDevicesLock, NULL);
    count = WdfCollectionGetCount(FilterDevices);

    response->Length = FIELD_OFFSET(PORTSNIFFER_GET_ATTACHED_PORTS_RESPONSE, PortNames);
    for (i = 0; i < count; i++)
    {
        device = WdfCollectionGetItem(FilterDevices, i);
        filterContext = GetFilterContext(device);
        response->Length += filterContext->PortName.Length + sizeof(WCHAR);
    }

    response->Length += sizeof(WCHAR);

    // Check if the provided buffer is large enough.
    if (responseBufferLength >= response->Length)
    {
        // Copy the port names to the provided buffer.
        // They are separated by NUL terminators, with a final NUL to terminate the string sequence (just like REG_MULTI_SZ).
        p = response->PortNames;
        for (i = 0; i < count; i++)
        {
            device = WdfCollectionGetItem(FilterDevices, i);
            filterContext = GetFilterContext(device);

            RtlCopyMemory(p, filterContext->PortName.Buffer, filterContext->PortName.Length);
            p += filterContext->PortName.Length / sizeof(WCHAR);
            *p = L'\0';
            p++;
        }

        *p = L'\0';
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, response->Length);
    }
    else
    {
        // Return only the Length field containing the required buffer size.
        WdfRequestCompleteWithInformation(Request, STATUS_BUFFER_OVERFLOW, sizeof(ULONG));
    }

    WdfWaitLockRelease(FilterDevicesLock);
}

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferControlGetVersion(
    __in WDFREQUEST Request
    )
{
    PPORTSNIFFER_GET_VERSION_RESPONSE response;
    NTSTATUS status;

    PAGED_CODE();
    KdPrint(("PortSnifferControlGetVersion(%p)\n", Request));

    status = WdfRequestRetrieveOutputBuffer(Request, sizeof(PORTSNIFFER_GET_VERSION_RESPONSE), &response, NULL);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfRequestRetrieveOutputBuffer failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
        return;
    }

    response->MajorVersion = PORTSNIFFER_MAJOR_VERSION;
    response->MinorVersion = PORTSNIFFER_MINOR_VERSION;

    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(PORTSNIFFER_GET_VERSION_RESPONSE));
}

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferControlPopPortLogEntry(
    __in WDFREQUEST Request
    )
{
    ULONG count;
    WDFDEVICE device;
    PFILTER_CONTEXT filterContext;
    ULONG i;
    PPORTSNIFFER_POP_PORTLOG_ENTRY_REQUEST popRequest;
    PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE response;
    ULONG_PTR responseLength = 0;
    NTSTATUS status;
    UNICODE_STRING unicodePortName;

    PAGED_CODE();
    KdPrint(("PortSnifferControlPopPortLogEntry(%p)\n", Request));

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(PORTSNIFFER_POP_PORTLOG_ENTRY_REQUEST), &popRequest, NULL);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfRequestRetrieveInputBuffer failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
        return;
    }

    status = WdfRequestRetrieveOutputBuffer(Request, PORTSNIFFER_PORTLOG_ENTRY_LENGTH, &response, NULL);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfRequestRetrieveOutputBuffer failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
        return;
    }

    // The caller may have sent us a non-NUL-terminated buffer, causing a buffer overrun if fed directly to wcscmp.
    // Avoid that by NUL-terminating the last possible character ourselves.
    popRequest->PortName[PORTSNIFFER_PORTNAME_LENGTH - 1] = L'\0';
    RtlInitUnicodeString(&unicodePortName, popRequest->PortName);

    // Look for the requested port name.
    status = STATUS_NO_SUCH_DEVICE;
    WdfWaitLockAcquire(FilterDevicesLock, NULL);
    count = WdfCollectionGetCount(FilterDevices);

    for (i = 0; i < count; i++)
    {
        device = WdfCollectionGetItem(FilterDevices, i);
        filterContext = GetFilterContext(device);

        if (RtlCompareUnicodeString(&filterContext->PortName, &unicodePortName, TRUE) == 0)
        {
            status = PortSnifferControlPopPortLogEntryInternal(filterContext, response, &responseLength);
            
            if (status == STATUS_NO_MORE_ENTRIES)
            {
                // No logs currently available. Park the request so it can be completed as soon as a log arrives.
                WdfWaitLockAcquire(filterContext->LogEntryLock, NULL);
                if (filterContext->LogEntryCount == 0 && filterContext->PendingPopRequest == NULL)
                {
                    status = WdfRequestMarkCancelableEx(Request, PortSnifferEvtPendingPopRequestCancel);
                    if (NT_SUCCESS(status))
                    {
                        filterContext->PendingPopRequest = Request;
                        status = STATUS_PENDING;
                    }
                    else
                    {
                        // Request is already cancelled
                        status = STATUS_CANCELLED;
                    }
                }
                else if (filterContext->PendingPopRequest != NULL)
                {
                    // There's already a pending request for this port. This shouldn't happen with well-behaved clients.
                    status = STATUS_DEVICE_BUSY;
                }
                else
                {
                    // A log arrived right after we checked but before we seized the lock! Let's pop it now.
                    WdfWaitLockRelease(filterContext->LogEntryLock);
                    status = PortSnifferControlPopPortLogEntryInternal(filterContext, response, &responseLength);
                    break;
                }
                WdfWaitLockRelease(filterContext->LogEntryLock);
            }
            break;
        }
    }

    WdfWaitLockRelease(FilterDevicesLock);

    // If the request was parked as pending, do NOT complete it here — it will
    // be completed later either by PortSnifferFilterAddPortLogEntry when a log
    // arrives or by PortSnifferEvtPendingPopRequestCancel on cancellation.
    if (status != STATUS_PENDING)
    {
        WdfRequestCompleteWithInformation(Request, status, responseLength);
    }
}

__drv_requiresIRQL(PASSIVE_LEVEL)
NTSTATUS
PortSnifferControlPopPortLogEntryInternal(
    __inout PFILTER_CONTEXT FilterContext,
    __out PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE Response,
    __out PULONG_PTR ResponseLength
    )
{
    PPORTLOG_ENTRY entry;
    NTSTATUS status;

    PAGED_CODE();
    KdPrint(("PortSnifferControlPopPortLogEntryInternal(%p, %p, %p)\n", FilterContext, Response, ResponseLength));

    WdfWaitLockAcquire(FilterContext->LogEntryLock, NULL);

    if (FilterContext->LogEntryCount > 0)
    {
        // Get the first log entry and copy its information to the response buffer.
        entry = FilterContext->LogEntryHead;
        *ResponseLength = FIELD_OFFSET(PORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE, Data) + entry->Response.DataLength;
        RtlCopyMemory(Response, &entry->Response, *ResponseLength);

        // Remove the entry from the list.
        if (FilterContext->LogEntryTail == entry)
        {
            FilterContext->LogEntryTail = NULL;
        }

        FilterContext->LogEntryHead = entry->Next;
        FilterContext->LogEntryCount--;

        // Return its memory back to the lookaside list.
        WdfObjectDelete(entry->Memory);

        status = STATUS_SUCCESS;
    }
    else
    {
        *ResponseLength = 0;
        status = STATUS_NO_MORE_ENTRIES;
    }

    WdfWaitLockRelease(FilterContext->LogEntryLock);

    return status;
}

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferControlResetPortMonitoring(
    __in WDFREQUEST Request
    )
{
    ULONG count;
    WDFDEVICE device;
    PFILTER_CONTEXT filterContext;
    ULONG i;
    PPORTSNIFFER_RESET_PORT_MONITORING_REQUEST portMonitoringRequest;
    NTSTATUS status;
    UNICODE_STRING unicodePortName;

    PAGED_CODE();
    KdPrint(("PortSnifferControlResetPortMonitoring(%p)\n", Request));

    status = WdfRequestRetrieveInputBuffer(Request, sizeof(PORTSNIFFER_RESET_PORT_MONITORING_REQUEST), &portMonitoringRequest, NULL);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfRequestRetrieveInputBuffer failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
        return;
    }

    // The caller may have sent us a non-NUL-terminated buffer, causing a buffer overrun if fed directly to wcscmp.
    // Avoid that by NUL-terminating the last possible character ourselves.
    portMonitoringRequest->PortName[PORTSNIFFER_PORTNAME_LENGTH - 1] = L'\0';
    RtlInitUnicodeString(&unicodePortName, portMonitoringRequest->PortName);

    // Look for the requested port name.
    status = STATUS_NO_SUCH_DEVICE;
    WdfWaitLockAcquire(FilterDevicesLock, NULL);
    count = WdfCollectionGetCount(FilterDevices);

    for (i = 0; i < count; i++)
    {
        device = WdfCollectionGetItem(FilterDevices, i);
        filterContext = GetFilterContext(device);

        if (RtlCompareUnicodeString(&filterContext->PortName, &unicodePortName, TRUE) == 0)
        {
            // Set the new monitor mask, clear recorded events, and exit the loop.
            filterContext->MonitorMask = portMonitoringRequest->MonitorMask;
            PortSnifferFilterClearPortLog(filterContext);
            status = STATUS_SUCCESS;
            break;
        }
    }

    WdfWaitLockRelease(FilterDevicesLock);
    WdfRequestComplete(Request, status);
}

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferFilterAddPortLogEntry(
    __inout PFILTER_CONTEXT FilterContext,
    __in USHORT Type,
    __in PUCHAR Data,
    __in size_t DataLength
    )
{
    // We can fit up to PORTSNIFFER_PORTLOG_ENTRY_LENGTH bytes into the response buffer provided by the tool.
    // The actual data may consume everything that's left after the response header.
    const USHORT MaxDataLength = PORTSNIFFER_PORTLOG_ENTRY_LENGTH - FIELD_OFFSET(PORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE, Data);

    PPORTLOG_ENTRY entry;
    WDFMEMORY entryMemory;
    NTSTATUS status;
    NTSTATUS outStatus = STATUS_SUCCESS;
    WDFREQUEST requestToComplete = NULL;
    ULONG_PTR requestToCompleteLength = 0;
    NTSTATUS requestToCompleteStatus = STATUS_SUCCESS;

    PAGED_CODE();
    KdPrint(("PortSnifferFilterAddPortLogEntry(%p, %x, %p, %Iu)\n", FilterContext, Type, Data, DataLength));

    WdfWaitLockAcquire(FilterContext->LogEntryLock, NULL);

    // Don't add anything if the application hasn't popped entries for some time.
    if (FilterContext->LogEntryCount >= MAX_LOG_ENTRIES_PER_PORT)
    {
        KdPrint(("List is full, not adding log entry\n"));
        goto Cleanup;
    }

    // Allocate a new log entry of PORTSNIFFER_PORTLOG_ENTRY_LENGTH bytes from our lookaside list.
    status = WdfMemoryCreateFromLookaside(PortLogLookaside, &entryMemory);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfMemoryCreateFromLookaside failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Truncate any data that goes beyond our maximum supported length.
    if (DataLength > MaxDataLength)
    {
        KdPrint(("Truncating log entry data from %Iu to %u bytes\n", DataLength, MaxDataLength));
        DataLength = MaxDataLength;
    }

    // Set all log entry information.
    entry = WdfMemoryGetBuffer(entryMemory, NULL);
    entry->Memory = entryMemory;
    entry->Next = NULL;
    KeQuerySystemTime(&entry->Response.Timestamp);
    entry->Response.Type = Type;
    entry->Response.DataLength = (USHORT)DataLength;
    RtlCopyMemory(entry->Response.Data, Data, DataLength);

    // Add us to the end of the list.
    if (FilterContext->LogEntryCount > 0)
    {
        FilterContext->LogEntryTail->Next = entry;
    }
    else
    {
        FilterContext->LogEntryHead = entry;
    }

    FilterContext->LogEntryTail = entry;
    FilterContext->LogEntryCount++;

    // Satisfy a pending uncancelled pop request if there is one.
    if (FilterContext->PendingPopRequest != NULL)
    {
        WDFREQUEST pendingRequest = FilterContext->PendingPopRequest;
        NTSTATUS unmarkStatus;
        
        // Try to unmark cancelable. If it returns STATUS_CANCELLED, the cancellation
        // routine is already running or will run, so we must not complete the request ourselves.
        unmarkStatus = WdfRequestUnmarkCancelable(pendingRequest);
        if (unmarkStatus != STATUS_CANCELLED)
        {
            // We successfully revoked cancellation, meaning we now OWN completing this request.
            PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE outResponse;
            ULONG_PTR outLength = 0;
            
            FilterContext->PendingPopRequest = NULL; // We are processing it
            
            // Pop the entry we just inserted!
            // Wait, we DO NOT call PortSnifferControlPopPortLogEntryInternal because we hold the LogEntryLock!
            // We just do the extraction manually since we are under the lock.
            outStatus = WdfRequestRetrieveOutputBuffer(pendingRequest, PORTSNIFFER_PORTLOG_ENTRY_LENGTH, &outResponse, NULL);
            if (NT_SUCCESS(outStatus))
            {
                PPORTLOG_ENTRY popEntry = FilterContext->LogEntryHead;
                outLength = FIELD_OFFSET(PORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE, Data) + popEntry->Response.DataLength;
                RtlCopyMemory(outResponse, &popEntry->Response, outLength);

                if (FilterContext->LogEntryTail == popEntry)
                {
                    FilterContext->LogEntryTail = NULL;
                }
                FilterContext->LogEntryHead = popEntry->Next;
                FilterContext->LogEntryCount--;
                WdfObjectDelete(popEntry->Memory);
            }
            
            // We must complete the request OUTSIDE of the spin/wait lock, so we queue a DPC or worker?
            // Actually WaitLock is PASSIVE_LEVEL, we can safely complete the request right after releasing the lock.
            // Oh wait, WdfWaitLockAcquire might be held contextually. WdfRequestComplete might invoke user APCs or callbacks.
            // It is generally safe to call WdfRequestComplete without a lock.
            // We will complete it after jumping to cleanup, by storing it in a local variable.
            requestToComplete = pendingRequest;
            requestToCompleteLength = outLength;
            requestToCompleteStatus = outStatus;
        }
    }

Cleanup:
    WdfWaitLockRelease(FilterContext->LogEntryLock);

    if (requestToComplete != NULL)
    {
        WdfRequestCompleteWithInformation(requestToComplete, requestToCompleteStatus, requestToCompleteLength);
    }
}

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferEvtPendingPopRequestCancel(
    __in WDFREQUEST Request
    )
{
    // The request was cancelled by the user. We must remove it from PendingPopRequest and complete it.
    // However, we don't naturally know WHICH FilterContext owns this request!
    // But we CAN find out by searching all filter devices.
    ULONG count;
    WDFDEVICE device;
    PFILTER_CONTEXT filterContext;
    ULONG i;

    // We don't PAGED_CODE() since cancel routines can run at DISPATCH_LEVEL in some cases,
    // though WDF wait locks require PASSIVE_LEVEL. Wait locks are OK here since we created the 
    // driver with ExecutionLevelPassive.
    WdfWaitLockAcquire(FilterDevicesLock, NULL);
    count = WdfCollectionGetCount(FilterDevices);

    for (i = 0; i < count; i++)
    {
        device = WdfCollectionGetItem(FilterDevices, i);
        filterContext = GetFilterContext(device);
        
        WdfWaitLockAcquire(filterContext->LogEntryLock, NULL);
        if (filterContext->PendingPopRequest == Request)
        {
            filterContext->PendingPopRequest = NULL;
            WdfWaitLockRelease(filterContext->LogEntryLock);
            break;
        }
        WdfWaitLockRelease(filterContext->LogEntryLock);
    }
    WdfWaitLockRelease(FilterDevicesLock);

    WdfRequestComplete(Request, STATUS_CANCELLED);
}

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferFilterClearPortLog(
    __inout PFILTER_CONTEXT FilterContext
    )
{
    PPORTLOG_ENTRY entry;
    PPORTLOG_ENTRY nextEntry;

    PAGED_CODE();
    KdPrint(("PortSnifferFilterClearPortLog(%p)\n", FilterContext));

    WdfWaitLockAcquire(FilterContext->LogEntryLock, NULL);

    // Return the memory for each entry back to the lookaside list.
    for (entry = FilterContext->LogEntryHead; entry; entry = nextEntry)
    {
        nextEntry = entry->Next;
        WdfObjectDelete(entry->Memory);
    }

    // Clear the bookkeeping information.
    FilterContext->LogEntryHead = NULL;
    FilterContext->LogEntryTail = NULL;
    FilterContext->LogEntryCount = 0;

    WdfWaitLockRelease(FilterContext->LogEntryLock);
}

__drv_functionClass(EVT_WDF_DRIVER_DEVICE_ADD)
__drv_sameIRQL
__drv_maxIRQL(PASSIVE_LEVEL)
NTSTATUS
PortSnifferFilterEvtDeviceAdd(
    __in WDFDRIVER Driver,
    __inout PWDFDEVICE_INIT DeviceInit
    )
{
    DECLARE_CONST_UNICODE_STRING(portNameValueName, L"PortName");

    WDFDEVICE device;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    PFILTER_CONTEXT filterContext;
    WDF_OBJECT_ATTRIBUTES ioQueueAttributes;
    WDF_IO_QUEUE_CONFIG ioQueueConfig;
    WDF_OBJECT_ATTRIBUTES logEntryLockAttributes;
    WDFSTRING portNameValueData;
    WDF_OBJECT_ATTRIBUTES portNameValueDataAttributes;
    WDF_IO_QUEUE_CONFIG readLogQueueConfig;
    WDF_OBJECT_ATTRIBUTES readLogQueueAttributes;
    WDFKEY regKey = WDF_NO_HANDLE;
    NTSTATUS status;
    UNICODE_STRING tempUnicodeString;

    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();
    KdPrint(("PortSnifferFilterEvtDeviceAdd(%p, %p)\n", Driver, DeviceInit));

    // Register us as a filter device.
    WdfFdoInitSetFilter(DeviceInit);

    // Register a callback to remove the device from the FilterDevices collection on teardown.
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, FILTER_CONTEXT);
    deviceAttributes.EvtCleanupCallback = PortSnifferFilterEvtDeviceCleanup;

    // Create our filter device and attach it to the stack of the port device.
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfDeviceCreate failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    WDFKEY hardwareKey = WDF_NO_HANDLE;
    UNICODE_STRING subkeyName;

    // Query the port name and store it in our context.
    status = WdfDeviceOpenRegistryKey(device, PLUGPLAY_REGKEY_DEVICE, KEY_READ, WDF_NO_OBJECT_ATTRIBUTES, &hardwareKey);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfDeviceOpenRegistryKey failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Allocate the string to hold the value.
    WDF_OBJECT_ATTRIBUTES_INIT(&portNameValueDataAttributes);
    portNameValueDataAttributes.ParentObject = device;
    status = WdfStringCreate(NULL, &portNameValueDataAttributes, &portNameValueData);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfStringCreate failed, status = 0x%08lX\n", status));
        // Need to close hardwareKey if we fail here, but let Cleanup handle it if we add a cleanup branch, or we can just close it later.
        goto Cleanup;
    }

    // Try to open the "Device Parameters" subkey where PortName is usually located.
    RtlInitUnicodeString(&subkeyName, L"Device Parameters");
    status = WdfRegistryOpenKey(hardwareKey, &subkeyName, KEY_READ, WDF_NO_OBJECT_ATTRIBUTES, &regKey);
    if (NT_SUCCESS(status))
    {
        // We successfully opened "Device Parameters". Try to read "PortName".
        status = WdfRegistryQueryString(regKey, &portNameValueName, portNameValueData);
        WdfRegistryClose(regKey);
    }

    if (!NT_SUCCESS(status))
    {
        // Fallback to "FriendlyName" from the root hardware key if "PortName" is not found or "Device Parameters" couldn't be opened.
        DECLARE_CONST_UNICODE_STRING(friendlyNameValueName, L"FriendlyName");
        status = WdfRegistryQueryString(hardwareKey, &friendlyNameValueName, portNameValueData);
    }
    
    // Always close the hardwareKey.
    if (hardwareKey)
    {
        WdfRegistryClose(hardwareKey);
    }

    if (!NT_SUCCESS(status))
    {
        KdPrint(("Could not retrieve PortName or FriendlyName, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    filterContext = GetFilterContext(device);
    filterContext->PortName.Buffer = filterContext->PortNameBuffer;
    filterContext->PortName.MaximumLength = sizeof(filterContext->PortNameBuffer);
    filterContext->PortName.Length = 0;

    WdfStringGetUnicodeString(portNameValueData, &tempUnicodeString);
    RtlCopyUnicodeString(&filterContext->PortName, &tempUnicodeString);

    // Some drivers store the port name with a trailing NUL byte in the registry.
    // Strip it to avoid comparison failures against NUL-terminated C strings.
    if (filterContext->PortName.Length >= sizeof(WCHAR) &&
        filterContext->PortName.Buffer[filterContext->PortName.Length / sizeof(WCHAR) - 1] == L'\0')
    {
        filterContext->PortName.Length -= sizeof(WCHAR);
    }

    KdPrint(("PortSniffer attached to %wZ\n", &filterContext->PortName));

    if (filterContext->PortName.Length >= PORTSNIFFER_PORTNAME_LENGTH * sizeof(WCHAR))
    {
        KdPrint(("PortName is too long: %wZ\n", &filterContext->PortName));
        status = STATUS_NAME_TOO_LONG;
        goto Cleanup;
    }

    // Initialize the remaining context fields.
    filterContext->MonitorMask = PORTSNIFFER_MONITOR_NONE;
    filterContext->InFilterDevicesCollection = FALSE;

    filterContext->LogEntryHead = NULL;
    filterContext->LogEntryTail = NULL;
    filterContext->LogEntryCount = 0;
    filterContext->PendingPopRequest = NULL;

    WDF_OBJECT_ATTRIBUTES_INIT(&logEntryLockAttributes);
    logEntryLockAttributes.ParentObject = device;
    status = WdfWaitLockCreate(&logEntryLockAttributes, &filterContext->LogEntryLock);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfWaitLockCreate failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Register callbacks for all requests we possibly want to monitor.
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchParallel);
    ioQueueConfig.EvtIoRead = PortSnifferFilterEvtIoRead;
    ioQueueConfig.EvtIoWrite = PortSnifferFilterEvtIoWrite;
    ioQueueConfig.EvtIoDeviceControl = PortSnifferFilterEvtIoDeviceControl;

    // Ensure that all callback routines are run at IRQL == PASSIVE_LEVEL as we are dealing with paged-pool memory there.
    WDF_OBJECT_ATTRIBUTES_INIT(&ioQueueAttributes);
    ioQueueAttributes.ExecutionLevel = WdfExecutionLevelPassive;

    // Set up an I/O Queue to handle requests to our filter device.
    status = WdfIoQueueCreate(device, &ioQueueConfig, &ioQueueAttributes, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfIoQueueCreate failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Create a manual-dispatch queue where completed read requests are forwarded.
    // This queue runs at PASSIVE_LEVEL and handles every completed read with its
    // own per-request context, eliminating the shared work-item race.
    WDF_IO_QUEUE_CONFIG_INIT(&readLogQueueConfig, WdfIoQueueDispatchManual);
    readLogQueueConfig.EvtIoRead = PortSnifferFilterEvtReadLogQueueIoRead;

    WDF_OBJECT_ATTRIBUTES_INIT(&readLogQueueAttributes);
    readLogQueueAttributes.ExecutionLevel = WdfExecutionLevelPassive;
    readLogQueueAttributes.ParentObject = device;

    status = WdfIoQueueCreate(device, &readLogQueueConfig, &readLogQueueAttributes, &filterContext->ReadLogQueue);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfIoQueueCreate (ReadLogQueue) failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    // Add this device to the collection. The control device already exists
    // (it was created once at DriverEntry and persists for the lifetime of the
    // driver in the multi-port variant).
    WdfWaitLockAcquire(FilterDevicesLock, NULL);
    status = WdfCollectionAdd(FilterDevices, device);
    if (!NT_SUCCESS(status))
    {
        WdfWaitLockRelease(FilterDevicesLock);
        KdPrint(("WdfCollectionAdd failed, status = 0x%08lX\n", status));
        goto Cleanup;
    }

    KdPrint(("Device %wZ successfully added to FilterDevices collection\n", &filterContext->PortName));
    filterContext->InFilterDevicesCollection = TRUE;
    WdfWaitLockRelease(FilterDevicesLock);
    status = STATUS_SUCCESS;

Cleanup:
    if (regKey != WDF_NO_HANDLE)
    {
        WdfRegistryClose(regKey);
    }

    return status;
}

void
PortSnifferFilterEvtDeviceCleanup(
    WDFDEVICE Device
    )
{
    PFILTER_CONTEXT filterContext;

    PAGED_CODE();
    KdPrint(("PortSnifferFilterEvtDeviceCleanup(%p)\n", Device));

    filterContext = GetFilterContext(Device);

    WdfWaitLockAcquire(FilterDevicesLock, NULL);

    // Only touch the collection if EvtDeviceAdd actually finished adding us.
    // The control device is owned by the driver lifetime and is freed by the
    // framework on driver unload — we do not delete it here.
    if (filterContext->InFilterDevicesCollection)
    {
        WdfCollectionRemove(FilterDevices, Device);
        filterContext->InFilterDevicesCollection = FALSE;
    }

    WdfWaitLockRelease(FilterDevicesLock);
}

__drv_functionClass(EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL)
__drv_sameIRQL
__drv_maxIRQL(DISPATCH_LEVEL)
void
PortSnifferFilterEvtIoDeviceControl(
    __in WDFQUEUE Queue,
    __in WDFREQUEST Request,
    __in size_t OutputBufferLength,
    __in size_t InputBufferLength,
    __in ULONG IoControlCode
    )
{
    WDFDEVICE device;
    PFILTER_CONTEXT filterContext;
    WDF_REQUEST_SEND_OPTIONS sendOptions;
    NTSTATUS status;
    WDFIOTARGET target;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    PAGED_CODE();
    KdPrint(("PortSnifferFilterEvtIoDeviceControl(%p, %p, %Iu, %Iu, %lX)\n", Queue, Request, OutputBufferLength, InputBufferLength, IoControlCode));

    device = WdfIoQueueGetDevice(Queue);
    filterContext = GetFilterContext(device);
    target = WdfDeviceGetIoTarget(device);
    WdfRequestFormatRequestUsingCurrentType(Request);

    if (filterContext->MonitorMask & PORTSNIFFER_MONITOR_IOCTL)
    {
        // We monitor I/O Device Control requests for this port.
        PortSnifferFilterEvtIoDeviceControlInternal(filterContext, Request, IoControlCode);
    }

    WDF_REQUEST_SEND_OPTIONS_INIT(&sendOptions, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);
    if (!WdfRequestSend(Request, target, &sendOptions))
    {
        status = WdfRequestGetStatus(Request);
        KdPrint(("WdfRequestSend failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
    }
}

__drv_requiresIRQL(PASSIVE_LEVEL)
void
PortSnifferFilterEvtIoDeviceControlInternal(
    __inout PFILTER_CONTEXT FilterContext,
    __in WDFREQUEST Request,
    __in ULONG IoControlCode
    )
{
    PUCHAR inputBuffer;
    size_t inputBufferLength;
    PORTSNIFFER_IOCTL_DATA ioctlData;
    NTSTATUS status;

    PAGED_CODE();
    KdPrint(("PortSnifferFilterEvtIoDeviceControlInternal(%p, %p, %lX)\n", FilterContext, Request, IoControlCode));

    switch (IoControlCode)
    {
        case IOCTL_SERIAL_SET_BAUD_RATE:
        case IOCTL_SERIAL_SET_HANDFLOW:
        case IOCTL_SERIAL_SET_LINE_CONTROL:
        case IOCTL_SERIAL_SET_QUEUE_SIZE:
        case IOCTL_SERIAL_SET_TIMEOUTS:
            // These IOCTLs come with an input buffer that contains the interesting information.
            status = WdfRequestRetrieveInputBuffer(Request, 0, &inputBuffer, &inputBufferLength);
            if (!NT_SUCCESS(status))
            {
                KdPrint(("WdfRequestRetrieveInputBuffer failed, status = 0x%08lX\n", status));
                return;
            }

            if (inputBufferLength > sizeof(ioctlData.u))
            {
                KdPrint(("inputBuffer is too large to be logged (%Iu bytes)\n", inputBufferLength));
                return;
            }

            RtlCopyMemory(&ioctlData.u, inputBuffer, inputBufferLength);

            // Fall-through

        case IOCTL_SERIAL_CLR_DTR:
        case IOCTL_SERIAL_CLR_RTS:
        case IOCTL_SERIAL_SET_BREAK_OFF:
        case IOCTL_SERIAL_SET_BREAK_ON:
        case IOCTL_SERIAL_SET_DTR:
        case IOCTL_SERIAL_SET_RTS:
        case IOCTL_SERIAL_SET_XON:
        case IOCTL_SERIAL_SET_XOFF:
            ioctlData.IoControlCode = IoControlCode;
            PortSnifferFilterAddPortLogEntry(FilterContext, PORTSNIFFER_MONITOR_IOCTL, (PUCHAR)&ioctlData, sizeof(ioctlData));
    }
}

__drv_functionClass(EVT_WDF_IO_QUEUE_IO_READ)
__drv_sameIRQL
__drv_maxIRQL(DISPATCH_LEVEL)
void
PortSnifferFilterEvtIoRead(
    __in WDFQUEUE Queue,
    __in WDFREQUEST Request,
    __in size_t Length
    )
{
    WDFDEVICE device;
    PFILTER_CONTEXT filterContext;
    WDFMEMORY outputMemory;
    WDF_REQUEST_SEND_OPTIONS sendOptions;
    BOOLEAN sendResult;
    NTSTATUS status;
    WDFIOTARGET target;

    UNREFERENCED_PARAMETER(Length);

    PAGED_CODE();
    KdPrint(("PortSnifferFilterEvtIoRead(%p, %p, %Iu)\n", Queue, Request, Length));

    device = WdfIoQueueGetDevice(Queue);
    filterContext = GetFilterContext(device);
    target = WdfDeviceGetIoTarget(device);
    WdfRequestFormatRequestUsingCurrentType(Request);

    if (filterContext->MonitorMask & PORTSNIFFER_MONITOR_READ)
    {
        // We monitor read requests for this port.
        // As an upper filter driver, we have to wait until lower drivers have filled the read buffer.
        status = WdfRequestRetrieveOutputMemory(Request, &outputMemory);
        if (!NT_SUCCESS(status))
        {
            KdPrint(("WdfRequestRetrieveOutputMemory failed, status = 0x%08lX\n", status));
            WdfRequestComplete(Request, status);
            return;
        }

        status = WdfIoTargetFormatRequestForRead(target, Request, outputMemory, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            KdPrint(("WdfIoTargetFormatRequestForRead failed, status = 0x%08lX\n", status));
            WdfRequestComplete(Request, status);
            return;
        }

        WdfRequestSetCompletionRoutine(Request, PortSnifferFilterEvtIoReadCompletionRoutine, filterContext);
        sendResult = WdfRequestSend(Request, target, WDF_NO_SEND_OPTIONS);
    }
    else
    {
        // We don't monitor read requests for this port.
        // Forward the request and we're done.
        WDF_REQUEST_SEND_OPTIONS_INIT(&sendOptions, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);
        sendResult = WdfRequestSend(Request, target, &sendOptions);
    }

    if (!sendResult)
    {
        status = WdfRequestGetStatus(Request);
        KdPrint(("WdfRequestSend failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
    }
}

void
PortSnifferFilterEvtIoReadCompletionRoutine(
    __in WDFREQUEST Request,
    __in WDFIOTARGET Target,
    __in PWDF_REQUEST_COMPLETION_PARAMS Params,
    __in WDFCONTEXT Context
    )
{
    PFILTER_CONTEXT filterContext;
    PREAD_REQUEST_CONTEXT readRequestContext;
    WDF_OBJECT_ATTRIBUTES readRequestContextAttributes;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Target);

    KdPrint(("PortSnifferFilterEvtIoReadCompletionRoutine(%p, %p, %p, %p)\n", Request, Target, Params, Context));

    if (!NT_SUCCESS(Params->IoStatus.Status) || Params->Parameters.Read.Length == 0)
    {
        WdfRequestComplete(Request, Params->IoStatus.Status);
        return;
    }

    // Attach a per-request context holding the info we need at PASSIVE_LEVEL.
    // Using WdfObjectAllocateContext means every concurrent read carries its
    // own independent state — no shared work item, no race.
    filterContext = (PFILTER_CONTEXT)Context;

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&readRequestContextAttributes, READ_REQUEST_CONTEXT);
    status = WdfObjectAllocateContext(Request, &readRequestContextAttributes, &readRequestContext);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfObjectAllocateContext failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;
    }

    readRequestContext->ReadBuffer = WdfMemoryGetBuffer(Params->Parameters.Read.Buffer, NULL);
    readRequestContext->BytesRead = Params->Parameters.Read.Length;
    readRequestContext->FilterContext = filterContext;

    // Forward to the manual-dispatch queue which runs at PASSIVE_LEVEL.
    // WdfRequestForwardToIoQueue is legal at IRQL <= DISPATCH_LEVEL.
    status = WdfRequestForwardToIoQueue(Request, filterContext->ReadLogQueue);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("WdfRequestForwardToIoQueue failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, STATUS_SUCCESS);
    }
}

__drv_functionClass(EVT_WDF_IO_QUEUE_IO_READ)
__drv_sameIRQL
__drv_maxIRQL(PASSIVE_LEVEL)
void
PortSnifferFilterEvtReadLogQueueIoRead(
    __in WDFQUEUE Queue,
    __in WDFREQUEST Request,
    __in size_t Length
    )
{
    PREAD_REQUEST_CONTEXT readRequestContext;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(Length);

    PAGED_CODE();
    KdPrint(("PortSnifferFilterEvtReadLogQueueIoRead(%p, %p, %Iu)\n", Queue, Request, Length));

    // Running at PASSIVE_LEVEL now — safe to touch paged pool / acquire wait locks.
    readRequestContext = GetReadRequestContext(Request);
    PortSnifferFilterAddPortLogEntry(readRequestContext->FilterContext,
        PORTSNIFFER_MONITOR_READ,
        readRequestContext->ReadBuffer,
        readRequestContext->BytesRead
    );

    WdfRequestComplete(Request, STATUS_SUCCESS);
}

__drv_functionClass(EVT_WDF_IO_QUEUE_IO_WRITE)
__drv_sameIRQL
__drv_maxIRQL(DISPATCH_LEVEL)
void
PortSnifferFilterEvtIoWrite(
    __in WDFQUEUE Queue,
    __in WDFREQUEST Request,
    __in size_t Length
    )
{
    PUCHAR buffer;
    WDFDEVICE device;
    PFILTER_CONTEXT filterContext;
    size_t length;
    WDF_REQUEST_SEND_OPTIONS sendOptions;
    NTSTATUS status;
    WDFIOTARGET target;

    UNREFERENCED_PARAMETER(Length);

    PAGED_CODE();
    KdPrint(("PortSnifferFilterEvtIoWrite(%p, %p, %Iu)\n", Queue, Request, Length));

    device = WdfIoQueueGetDevice(Queue);
    filterContext = GetFilterContext(device);
    target = WdfDeviceGetIoTarget(device);
    WdfRequestFormatRequestUsingCurrentType(Request);

    if (filterContext->MonitorMask & PORTSNIFFER_MONITOR_WRITE)
    {
        // We monitor write requests for this port.
        // As an upper filter driver, we can just get everything we need from the write buffer.
        status = WdfRequestRetrieveInputBuffer(Request, 0, &buffer, &length);
        if (!NT_SUCCESS(status))
        {
            KdPrint(("WdfRequestRetrieveInputBuffer failed, status = 0x%08lX\n", status));
            WdfRequestComplete(Request, status);
            return;
        }

        PortSnifferFilterAddPortLogEntry(filterContext, PORTSNIFFER_MONITOR_WRITE, buffer, length);
    }

    WDF_REQUEST_SEND_OPTIONS_INIT(&sendOptions, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);
    if (!WdfRequestSend(Request, target, &sendOptions))
    {
        status = WdfRequestGetStatus(Request);
        KdPrint(("WdfRequestSend failed, status = 0x%08lX\n", status));
        WdfRequestComplete(Request, status);
    }
}
