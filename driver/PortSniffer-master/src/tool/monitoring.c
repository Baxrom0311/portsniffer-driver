//
// PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
// Copyright 2020-2022 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
//
// SPDX-License-Identifier: MIT
//

#include "PortSniffer-Tool.h"

typedef struct _FLAG_TRANSLATION
{
    ULONG FlagBit;
    const char* pszFlagName;
}
FLAG_TRANSLATION;

static BOOL _bTerminationRequested = FALSE;


static BOOL WINAPI
_CtrlHandlerRoutine(
    __in DWORD dwCtrlType
    )
{
    UNREFERENCED_PARAMETER(dwCtrlType);

    _bTerminationRequested = TRUE;
    return TRUE;
}

static BOOL
_ParseTypes(
    __in PCWSTR pwszTypes,
    __out PUSHORT pMonitorMask
    )
{
    PCWSTR p;

    *pMonitorMask = 0;
    for (p = pwszTypes; *p; p++)
    {
        if (*p == L'R')
        {
            *pMonitorMask |= PORTSNIFFER_MONITOR_READ;
        }
        else if (*p == L'W')
        {
            *pMonitorMask |= PORTSNIFFER_MONITOR_WRITE;
        }
        else if (*p == L'C')
        {
            *pMonitorMask |= PORTSNIFFER_MONITOR_IOCTL;
        }
        else
        {
            fprintf(stderr, "Invalid character for TYPES: %lc\n", *p);
            return FALSE;
        }
    }

    if (*pMonitorMask == 0)
    {
        fprintf(stderr, "No TYPES to monitor were given.\n");
        return FALSE;
    }

    return TRUE;
}

static void
_PrintBitmask(
    __in ULONG Bitmask,
    __in const FLAG_TRANSLATION* TranslationTable,
    __in size_t TranslationTableEntries
    )
{
    BOOL bPrintedOne = FALSE;
    size_t i;

    for (i = 0; i < TranslationTableEntries; i++)
    {
        if (Bitmask & TranslationTable[i].FlagBit)
        {
            if (bPrintedOne)
            {
                printf("|");
            }

            printf("%s", TranslationTable[i].pszFlagName);
            bPrintedOne = TRUE;
        }
    }
}

static BOOL
_PrintIoctlResponse(
    __in PPORTSNIFFER_IOCTL_DATA pIoctlData
    )
{
    const FLAG_TRANSLATION ControlHandShakeTranslationTable[] = {
        { SERIAL_DTR_CONTROL, "SERIAL_DTR_CONTROL" },
        { SERIAL_DTR_HANDSHAKE, "SERIAL_DTR_HANDSHAKE" },
        { SERIAL_CTS_HANDSHAKE, "SERIAL_CTS_HANDSHAKE"},
        { SERIAL_DSR_HANDSHAKE, "SERIAL_DSR_HANDSHAKE" },
        { SERIAL_DCD_HANDSHAKE, "SERIAL_DCD_HANDSHAKE" },
        { SERIAL_DSR_SENSITIVITY, "SERIAL_DSR_SENSITIVITY" },
        { SERIAL_ERROR_ABORT, "SERIAL_ERROR_ABORT" }
    };
    const FLAG_TRANSLATION FlowReplaceTranslationTable[] = {
        { SERIAL_AUTO_TRANSMIT, "SERIAL_AUTO_TRANSMIT" },
        { SERIAL_AUTO_RECEIVE, "SERIAL_AUTO_RECEIVE" },
        { SERIAL_ERROR_CHAR, "SERIAL_ERROR_CHAR" },
        { SERIAL_NULL_STRIPPING, "SERIAL_NULL_STRIPPING" },
        { SERIAL_BREAK_CHAR, "SERIAL_BREAK_CHAR" },
        { SERIAL_RTS_CONTROL, "SERIAL_RTS_CONTROL" },
        { SERIAL_RTS_HANDSHAKE, "SERIAL_RTS_HANDSHAKE" },
        { SERIAL_XOFF_CONTINUE, "SERIAL_XOFF_CONTINUE" }
    };
    const char* pszParity[] = { "NO_PARITY", "ODD_PARITY", "EVEN_PARITY", "MARK_PARITY", "SPACE_PARITY" };
    const char* pszStopBits[] = { "STOP_BIT_1", "STOP_BITS_1_5", "STOP_BITS_2" };

    switch (pIoctlData->IoControlCode)
    {
        case IOCTL_SERIAL_CLR_DTR:
            printf("IOCTL_SERIAL_CLR_DTR");
            return TRUE;

        case IOCTL_SERIAL_CLR_RTS:
            printf("IOCTL_SERIAL_CLR_RTS");
            return TRUE;

        case IOCTL_SERIAL_SET_BAUD_RATE:
            printf("IOCTL_SERIAL_SET_BAUD_RATE: %lu", pIoctlData->u.SerialBaudRate.BaudRate);
            return TRUE;

        case IOCTL_SERIAL_SET_BREAK_OFF:
            printf("IOCTL_SERIAL_SET_BREAK_OFF");
            return TRUE;

        case IOCTL_SERIAL_SET_BREAK_ON:
            printf("IOCTL_SERIAL_SET_BREAK_ON");
            return TRUE;

        case IOCTL_SERIAL_SET_DTR:
            printf("IOCTL_SERIAL_SET_DTR");
            return TRUE;

        case IOCTL_SERIAL_SET_HANDFLOW:
            printf("IOCTL_SERIAL_SET_HANDFLOW: ControlHandShake:");
            _PrintBitmask(pIoctlData->u.SerialHandflow.ControlHandShake, ControlHandShakeTranslationTable, _countof(ControlHandShakeTranslationTable));
            printf(", FlowReplace:");
            _PrintBitmask(pIoctlData->u.SerialHandflow.FlowReplace, FlowReplaceTranslationTable, _countof(FlowReplaceTranslationTable));
            printf(", XonLimit:%ld, XoffLimit:%ld", pIoctlData->u.SerialHandflow.XonLimit, pIoctlData->u.SerialHandflow.XoffLimit);
            return TRUE;

        case IOCTL_SERIAL_SET_LINE_CONTROL:
        {
            printf("IOCTL_SERIAL_SET_LINE_CONTROL: ");

            if (pIoctlData->u.SerialLineControl.StopBits < _countof(pszStopBits))
            {
                printf("StopBits:%s, ", pszStopBits[pIoctlData->u.SerialLineControl.StopBits]);
            }

            if (pIoctlData->u.SerialLineControl.Parity < _countof(pszParity))
            {
                printf("Parity:%s, ", pszParity[pIoctlData->u.SerialLineControl.Parity]);
            }

            printf("WordLength:%u", pIoctlData->u.SerialLineControl.WordLength);
            return TRUE;
        }

        case IOCTL_SERIAL_SET_QUEUE_SIZE:
            printf("IOCTL_SERIAL_SET_QUEUE_SIZE: InSize:%lu, OutSize:%lu",
                   pIoctlData->u.SerialQueueSize.InSize,
                   pIoctlData->u.SerialQueueSize.OutSize);
            return TRUE;

        case IOCTL_SERIAL_SET_RTS:
            printf("IOCTL_SERIAL_SET_RTS");
            return TRUE;

        case IOCTL_SERIAL_SET_TIMEOUTS:
            printf("IOCTL_SERIAL_SET_TIMEOUTS: ReadIntervalTimeout:%lu, ReadTotalTimeoutMultiplier:%lu, ReadTotalTimeoutConstant:%lu, WriteTotalTimeoutMultiplier:%lu, WriteTotalTimeoutConstant:%lu",
                   pIoctlData->u.SerialTimeouts.ReadIntervalTimeout,
                   pIoctlData->u.SerialTimeouts.ReadTotalTimeoutMultiplier,
                   pIoctlData->u.SerialTimeouts.ReadTotalTimeoutConstant,
                   pIoctlData->u.SerialTimeouts.WriteTotalTimeoutMultiplier,
                   pIoctlData->u.SerialTimeouts.WriteTotalTimeoutConstant);
            return TRUE;

        case IOCTL_SERIAL_SET_XON:
            printf("IOCTL_SERIAL_SET_XON");
            return TRUE;

        case IOCTL_SERIAL_SET_XOFF:
            printf("IOCTL_SERIAL_SET_XOFF");
            return TRUE;

        default:
            fprintf(stderr, "Captured an unknown IOCTL code: 0x%08X\n", pIoctlData->IoControlCode);
            return FALSE;
    }
}

static BOOL
_PrintResponse(
    __in PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE pPopResponse,
    __in PCWSTR pwszPort
    )
{
    char cType;
    PFILETIME pFileTimeStamp;
    PPORTSNIFFER_IOCTL_DATA pIoctlData;
    SYSTEMTIME SystemTimeStamp;
    USHORT i;

    // Convert the timestamp into a printable format.
    // The LARGE_INTEGER Timestamp can be casted to a FILETIME (but not necessarily vice-versa!)
    pFileTimeStamp = (PFILETIME)&pPopResponse->Timestamp;
    FileTimeToSystemTime(pFileTimeStamp, &SystemTimeStamp);

    // Indicate the monitored request via a single character.
    if (pPopResponse->Type == PORTSNIFFER_MONITOR_READ)
    {
        cType = 'R';
    }
    else if (pPopResponse->Type == PORTSNIFFER_MONITOR_WRITE)
    {
        cType = 'W';
    }
    else if (pPopResponse->Type == PORTSNIFFER_MONITOR_IOCTL)
    {
        cType = 'C';
    }
    else
    {
        fprintf(stderr, "Captured an invalid request type: 0x%04X\n", pPopResponse->Type);
        return FALSE;
    }

    // Print in the format "UTC TIMESTAMP | PORT | TYPE | LENGTH | DATA".
    printf("%04u-%02u-%02u %02u:%02u:%02u.%03u | %S | %c | %4u |",
           SystemTimeStamp.wYear, SystemTimeStamp.wMonth, SystemTimeStamp.wDay,
           SystemTimeStamp.wHour, SystemTimeStamp.wMinute, SystemTimeStamp.wSecond, SystemTimeStamp.wMilliseconds,
           pwszPort, cType, pPopResponse->DataLength);

    if (pPopResponse->Type == PORTSNIFFER_MONITOR_IOCTL)
    {
        // IOCTLs need specialized printing depending on the IOCTL code.
        pIoctlData = (PPORTSNIFFER_IOCTL_DATA)pPopResponse->Data;
        printf(" ");

        if (!_PrintIoctlResponse(pIoctlData))
        {
            return FALSE;
        }
    }
    else
    {
        // For read and write requests, we just dump the bytes of the buffer.
        for (i = 0; i < pPopResponse->DataLength; i++)
        {
            printf(" %02X", pPopResponse->Data[i]);
        }
    }

    printf("\n");
    return TRUE;
}

static void _BytesToHex(__in_bcount(cb) const BYTE* pb, __in size_t cb, __out_ecount(cchOut) PWSTR pwszOut, __in size_t cchOut)
{
    static const WCHAR hexdigits[] = L"0123456789ABCDEF";
    size_t i;
    size_t pos = 0;
    for (i = 0; i < cb && pos + 2 < cchOut; i++)
    {
        pwszOut[pos++] = hexdigits[(pb[i] >> 4) & 0xF];
        pwszOut[pos++] = hexdigits[pb[i] & 0xF];
    }
    if (pos < cchOut) pwszOut[pos] = L'\0';
}

BOOL TryReadDefaultForwardUrl(
    __out_ecount(cchBuffer) PWSTR pwszBuffer,
    __in size_t cchBuffer
    )
{
    WCHAR wszExePath[MAX_PATH];
    WCHAR wszDir[MAX_PATH];
    WCHAR wszCfgPath[MAX_PATH];
    DWORD len;
    WCHAR* p;
    HANDLE h;
    BYTE buf[2048];
    DWORD cbRead;
    BOOL ok;
    const char* start;
    const char* line;
    const char* end;
    const char* key;
    size_t keylen;
    int cch;

    len = GetModuleFileNameW(NULL, wszExePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
        return FALSE;

    // Extract directory
    wcscpy_s(wszDir, MAX_PATH, wszExePath);
    p = wcsrchr(wszDir, L'\\');
    if (!p) return FALSE;
    *p = L'\0';

    if (FAILED(StringCchPrintfW(wszCfgPath, MAX_PATH, L"%s\\PortSniffer-Tool.config", wszDir)))
        return FALSE;

    h = CreateFileW(wszCfgPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;

    cbRead = 0;
    ok = ReadFile(h, buf, sizeof(buf) - 2, &cbRead, NULL);
    CloseHandle(h);
    if (!ok || cbRead == 0)
        return FALSE;
    buf[cbRead] = '\0';
    buf[cbRead + 1] = '\0';

    // Very simple parse: look for "forward_url=" at start of any line
    start = (const char*)buf;
    line = start;
    while (*line)
    {
        while (*line == '\r' || *line == '\n') line++;
        if (!*line) break;
        end = line;
        while (*end && *end != '\r' && *end != '\n') end++;

        key = "forward_url=";
        keylen = 12;
        if ((size_t)(end - line) > keylen && _strnicmp(line, key, keylen) == 0)
        {
            // Copy value as UTF-8 bytes -> convert to wide
            cch = MultiByteToWideChar(CP_UTF8, 0, line + keylen, (int)(end - (line + keylen)), pwszBuffer, (int)cchBuffer);
            if (cch > 0)
            {
                pwszBuffer[min((size_t)cch, cchBuffer - 1)] = L'\0';
                return TRUE;
            }
        }
        line = (*end ? end + 1 : end);
    }
    return FALSE;
}

// Minimal URL parser (supports http/https)
static BOOL _ParseUrl(__in PCWSTR pwszUrl, __out_ecount(cchHost) PWSTR pwszHost, size_t cchHost, __out_ecount(cchPath) PWSTR pwszPath, size_t cchPath, __out USHORT* pPort, __out BOOL* pHttps)
{
    const WCHAR* s;
    const WCHAR* slash;
    const WCHAR* hostEnd;
    const WCHAR* colon;
    const WCHAR* piter;

    *pHttps = FALSE;
    *pPort = 0;
    pwszHost[0] = L'\0';
    pwszPath[0] = L'\0';

    s = pwszUrl;
    if (_wcsnicmp(s, L"https://", 8) == 0) { *pHttps = TRUE; s += 8; }
    else if (_wcsnicmp(s, L"http://", 7) == 0) { *pHttps = FALSE; s += 7; }
    else { return FALSE; }

    slash = wcschr(s, L'/');
    hostEnd = slash ? slash : s + wcslen(s);
    colon = NULL;
    for (piter = s; piter < hostEnd; ++piter)
    {
        if (*piter == L':') { colon = piter; break; }
    }

    if (colon)
    {
        StringCchCopyNW(pwszHost, cchHost, s, colon - s);
        *pPort = (USHORT)_wtoi(colon + 1);
    }
    else
    {
        StringCchCopyNW(pwszHost, cchHost, s, hostEnd - s);
        *pPort = *pHttps ? 443 : 80;
    }
    if (slash) StringCchCopyW(pwszPath, cchPath, slash);
    else StringCchCopyW(pwszPath, cchPath, L"/");
    return pwszHost[0] != L'\0';
}

// Dynamic WinHTTP binding to keep WDK 7.1 compatible without SDK winhttp headers/libs
typedef LPVOID HINTERNET;
typedef HINTERNET (WINAPI *PFN_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *PFN_WinHttpConnect)(HINTERNET, LPCWSTR, USHORT, DWORD);
typedef HINTERNET (WINAPI *PFN_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI *PFN_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *PFN_WinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL (WINAPI *PFN_WinHttpCloseHandle)(HINTERNET);

#ifndef WINHTTP_FLAG_SECURE
#define WINHTTP_FLAG_SECURE 0x00800000
#endif

BOOL SendLogEntryToApi(
    __in PCWSTR pwszUrl,
    __in PCWSTR pwszPort,
    __in PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE pEntry
    )
{
    WCHAR host[256];
    WCHAR path[1024];
    USHORT port;
    BOOL https;
    HMODULE h;
    PFN_WinHttpOpen pOpen;
    PFN_WinHttpConnect pConnect;
    PFN_WinHttpOpenRequest pOpenRequest;
    PFN_WinHttpSendRequest pSend;
    PFN_WinHttpReceiveResponse pRecv;
    PFN_WinHttpCloseHandle pClose;
    HINTERNET hSession;
    HINTERNET hConn;
    HINTERNET hReq;
    DWORD flags;
    SYSTEMTIME st;
    FILETIME ft;
    WCHAR wszHex[PORTSNIFFER_PORTLOG_ENTRY_LENGTH * 2 + 1];
    WCHAR json[8192];
    BOOL ok;

    if (!_ParseUrl(pwszUrl, host, _countof(host), path, _countof(path), &port, &https))
    {
        fprintf(stderr, "Invalid URL: %S\n", pwszUrl);
        return FALSE;
    }

    h = LoadLibraryW(L"winhttp.dll");
    if (!h) { fprintf(stderr, "winhttp.dll not found.\n"); return FALSE; }

    pOpen = (PFN_WinHttpOpen)GetProcAddress(h, "WinHttpOpen");
    pConnect = (PFN_WinHttpConnect)GetProcAddress(h, "WinHttpConnect");
    pOpenRequest = (PFN_WinHttpOpenRequest)GetProcAddress(h, "WinHttpOpenRequest");
    pSend = (PFN_WinHttpSendRequest)GetProcAddress(h, "WinHttpSendRequest");
    pRecv = (PFN_WinHttpReceiveResponse)GetProcAddress(h, "WinHttpReceiveResponse");
    pClose = (PFN_WinHttpCloseHandle)GetProcAddress(h, "WinHttpCloseHandle");
    if (!pOpen || !pConnect || !pOpenRequest || !pSend || !pRecv || !pClose)
    { FreeLibrary(h); return FALSE; }

    hSession = pOpen(L"PortSniffer-Tool/1.0", 0, NULL, NULL, 0);
    if (!hSession) { FreeLibrary(h); return FALSE; }
    hConn = pConnect(hSession, host, port, 0);
    if (!hConn) { pClose(hSession); FreeLibrary(h); return FALSE; }
    flags = https ? WINHTTP_FLAG_SECURE : 0;
    hReq = pOpenRequest(hConn, L"POST", path, NULL, NULL, NULL, flags);
    if (!hReq) { pClose(hConn); pClose(hSession); FreeLibrary(h); return FALSE; }

    ft = *(PFILETIME)&pEntry->Timestamp; FileTimeToSystemTime(&ft, &st);
    _BytesToHex(pEntry->Data, pEntry->DataLength, wszHex, _countof(wszHex));
    StringCchPrintfW(json, _countof(json),
        L"{\"port\":\"%s\",\"timestamp\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\",\"type\":%u,\"length\":%u,\"data_hex\":\"%s\"}",
        pwszPort,
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        (unsigned)pEntry->Type,
        (unsigned)pEntry->DataLength,
        wszHex);

    ok = pSend(hReq, L"Content-Type: application/json\r\n", (DWORD)-1L, (LPVOID)json, (DWORD)(wcslen(json) * sizeof(WCHAR)), (DWORD)(wcslen(json) * sizeof(WCHAR)), 0);
    if (ok) ok = pRecv(hReq, NULL);

    pClose(hReq); pClose(hConn); pClose(hSession); FreeLibrary(h);
    return ok;
}

int
HandleMonitorParameter(
    __in PCWSTR pwszPort,
    __in PCWSTR pwszTypes,
    __in_opt PCWSTR pwszForwardUrl
    )
{
    PCWSTR ports[1];
    ports[0] = pwszPort;
    return HandleMonitorParameterMulti(ports, 1, pwszTypes, pwszForwardUrl);
}

int
HandleMonitorParameterMulti(
    __in_ecount(nPortCount) PCWSTR* pwszPorts,
    __in unsigned int nPortCount,
    __in PCWSTR pwszTypes,
    __in_opt PCWSTR pwszForwardUrl
    )
{
    BOOL bMonitoringStarted = FALSE;
    DWORD cbReturned;
    HANDLE hPortSniffer = INVALID_HANDLE_VALUE;
    int iReturnValue = 1;
    unsigned int iPortIdx = 0;
    BYTE PopResponseBuffer[PORTSNIFFER_PORTLOG_ENTRY_LENGTH];
    PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE pPopResponse = (PPORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE)PopResponseBuffer;
    PORTSNIFFER_POP_PORTLOG_ENTRY_REQUEST PopRequest[MAX_MONITORING_PORTS];
    PORTSNIFFER_RESET_PORT_MONITORING_REQUEST ResetPortMonitoringRequest[MAX_MONITORING_PORTS];
    WCHAR wszForward[1024];

    // Limit to supported maximum
    if (nPortCount > MAX_MONITORING_PORTS)
        nPortCount = MAX_MONITORING_PORTS;

    // Check the input parameters and prepare the IOCTL requests.
    for (iPortIdx = 0; iPortIdx < nPortCount; iPortIdx++)
    {
        if (wcslen(pwszPorts[iPortIdx]) >= PORTSNIFFER_PORTNAME_LENGTH)
        {
            fprintf(stderr, "Port name is too long: %S\n", pwszPorts[iPortIdx]);
            goto Cleanup;
        }

        StringCchCopyW(PopRequest[iPortIdx].PortName, PORTSNIFFER_PORTNAME_LENGTH, pwszPorts[iPortIdx]);
        StringCchCopyW(ResetPortMonitoringRequest[iPortIdx].PortName, PORTSNIFFER_PORTNAME_LENGTH, pwszPorts[iPortIdx]);

        if (!_ParseTypes(pwszTypes, &ResetPortMonitoringRequest[iPortIdx].MonitorMask))
        {
            goto Cleanup;
        }
    }

    // Connect to our driver.
    hPortSniffer = OpenPortSniffer();
    if (hPortSniffer == INVALID_HANDLE_VALUE)
    {
        goto Cleanup;
    }

    // Verify that driver and tool are compatible.
    if (!VerifyDriverAndToolVersions(hPortSniffer, FALSE, NULL))
    {
        goto Cleanup;
    }

    // Start monitoring on all ports.
    for (iPortIdx = 0; iPortIdx < nPortCount; iPortIdx++)
    {
        if (!DeviceIoControl(hPortSniffer,
            (DWORD)PORTSNIFFER_IOCTL_CONTROL_RESET_PORT_MONITORING,
            &ResetPortMonitoringRequest[iPortIdx],
            sizeof(PORTSNIFFER_RESET_PORT_MONITORING_REQUEST),
            NULL,
            0,
            &cbReturned,
            NULL))
        {
            if (GetLastError() == ERROR_FILE_NOT_FOUND)
            {
                fprintf(stderr, "The PortSniffer Driver is not attached to %S!\n", ResetPortMonitoringRequest[iPortIdx].PortName);
                fprintf(stderr, "Please run this tool using the /attach option.\n");
            }
            else
            {
                fprintf(stderr, "DeviceIoControl failed for PORTSNIFFER_IOCTL_CONTROL_RESET_PORT_MONITORING, last error is %lu.\n", GetLastError());
            }

            goto Cleanup;
        }
    }

    bMonitoringStarted = TRUE;

    // Handle Ctrl+C requests to gracefully stop monitoring.
    if (!SetConsoleCtrlHandler(_CtrlHandlerRoutine, TRUE))
    {
        fprintf(stderr, "SetConsoleCtrlHandler failed, last error is %lu.\n", GetLastError());
        goto Cleanup;
    }

    // Determine forward URL (CLI or config)
    wszForward[0] = L'\0';
    if (pwszForwardUrl && *pwszForwardUrl)
    {
        StringCchCopyW(wszForward, _countof(wszForward), pwszForwardUrl);
    }
    else
    {
        TryReadDefaultForwardUrl(wszForward, _countof(wszForward));
    }

    // Print the table header.
    printf("UTC TIMESTAMP           | PORT | T |  LEN | DATA\n");

    // Fetch new port log entries from our driver until we are terminated.
    while (!_bTerminationRequested)
    {
        unsigned int noMore = 0;
        for (iPortIdx = 0; iPortIdx < nPortCount; iPortIdx++)
        {
            if (!DeviceIoControl(hPortSniffer,
                (DWORD)PORTSNIFFER_IOCTL_CONTROL_POP_PORTLOG_ENTRY,
                &PopRequest[iPortIdx],
                sizeof(PORTSNIFFER_POP_PORTLOG_ENTRY_REQUEST),
                PopResponseBuffer,
                sizeof(PopResponseBuffer),
                &cbReturned,
                NULL))
            {
                if (GetLastError() == ERROR_NO_MORE_ITEMS)
                {
                    noMore++;
                    continue;
                }
                else if (GetLastError() == ERROR_FILE_NOT_FOUND)
                {
                    fprintf(stderr, "The PortSniffer Driver is no longer attached to %S!\n", PopRequest[iPortIdx].PortName);
                    fprintf(stderr, "Please run this tool using the /attach option.\n");
                    goto Cleanup;
                }
                else
                {
                    fprintf(stderr, "DeviceIoControl failed for PORTSNIFFER_POP_PORTLOG_ENTRY_REQUEST, last error is %lu.\n", GetLastError());
                    goto Cleanup;
                }
            }

            if (!_PrintResponse(pPopResponse, PopRequest[iPortIdx].PortName))
            {
                goto Cleanup;
            }

            if (wszForward[0] != L'\0')
            {
                SendLogEntryToApi(wszForward, PopRequest[iPortIdx].PortName, pPopResponse);
            }
        }

        if (noMore == nPortCount)
        {
            Sleep(10);
        }
    }

    iReturnValue = 0;

Cleanup:
    if (bMonitoringStarted)
    {
        // Tell our driver to stop monitoring now that we are gone.
        // Failure to do so won't really do any harm, but accumulate port log entries until we have MAX_LOG_ENTRIES_PER_PORT.
        for (iPortIdx = 0; iPortIdx < nPortCount; iPortIdx++)
        {
            ResetPortMonitoringRequest[iPortIdx].MonitorMask = PORTSNIFFER_MONITOR_NONE;
            DeviceIoControl(hPortSniffer,
                (DWORD)PORTSNIFFER_IOCTL_CONTROL_RESET_PORT_MONITORING,
                &ResetPortMonitoringRequest[iPortIdx],
                sizeof(PORTSNIFFER_RESET_PORT_MONITORING_REQUEST),
                NULL,
                0,
                &cbReturned,
                NULL);
        }
    }

    if (hPortSniffer != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hPortSniffer);
    }

    return iReturnValue;
}
