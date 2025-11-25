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
static DWORD gAggregateGapMs = 300; // default, can be overridden by config
typedef enum _DECODER_PROFILE { DECODER_RAW = 0, DECODER_TEXNO_UZ = 1, DECODER_TEXNO_UZ_ALT1 = 2 } DECODER_PROFILE;
static DECODER_PROFILE gDecoderProfile = DECODER_TEXNO_UZ;
static BOOL gCrcRequired = FALSE;

#define AGGREGATE_MAX_BYTES (PORTSNIFFER_PORTLOG_ENTRY_LENGTH * 4)

typedef struct _PENDING_AGGREGATE
{
    BOOL hasData;
    USHORT type;
    LARGE_INTEGER lastTimestamp;
    BYTE data[AGGREGATE_MAX_BYTES];
    USHORT length;
}
PENDING_AGGREGATE;


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

// --- Texno UZ decode helpers ---
static USHORT _Crc16Texno(__in_bcount(len) const BYTE* data, __in size_t len)
{
    USHORT crc = 0xFFFF;
    size_t i;
    for (i = 0; i < len; ++i)
    {
        crc ^= (USHORT)data[i];
        for (int b = 0; b < 8; ++b)
        {
            if (crc & 0x0001)
                crc = (crc >> 1) ^ 0xA001;
            else
                crc >>= 1;
        }
    }
    return crc;
}

static BOOL _CheckPacketTexno(__in_bcount(len) const BYTE* data, __in size_t len)
{
    if (len < 3) return FALSE;
    USHORT expected = (USHORT)(data[len - 2] | (data[len - 1] << 8));
    USHORT calc = _Crc16Texno(data, len - 2);
    return expected == calc;
}

typedef struct _TEXNO_DECODE
{
    BOOL isTexno;
    BOOL crcOk;
    int deviceId;
    const WCHAR* frameType; // L"flow", L"env", or L"unknown"
    double volumeLiters;
    unsigned long amount;
    int pressure;
    int temperature;
}
TEXNO_DECODE;

static void _DecodeTexno(__in_bcount(len) const BYTE* data, __in size_t len, __out TEXNO_DECODE* out)
{
    ZeroMemory(out, sizeof(*out));
    if (len < 3) { out->isTexno = FALSE; return; }
    out->isTexno = TRUE;
    out->deviceId = (int)data[0];
    out->crcOk = _CheckPacketTexno(data, len);
    out->frameType = L"unknown";
    // flow/status frame: len>=17, data[1]==0x03 and marker in data[10]
    if (len >= 17 && data[1] == 0x03 && (data[10] == 0xA3 || data[10] == 0xB3 || data[10] == 0xB1 || data[10] == 0xA1 || data[10] == 0xA2 || data[10] == 0xA0 || data[10] == 0x82 || data[10] == 0x83 || data[10] == 0x93 || data[10] == 0x80))
    {
        unsigned int volRaw = (unsigned int)(data[11] << 8) | (unsigned int)data[12];
        unsigned long amt = ((unsigned long)data[15] << 24) | ((unsigned long)data[16] << 16) | ((unsigned long)data[13] << 8) | (unsigned long)data[14];
        out->volumeLiters = (double)volRaw / 100.0;
        out->amount = amt;
        out->frameType = L"flow";
        return;
    }
    // env frame: len>=13, data[1]==0x03 and data[2]==0x0A
    if (len >= 13 && data[1] == 0x03 && data[2] == 0x0A)
    {
        int pressure = (int)((data[3] << 8) | data[4]);
        int temperature = (int)((data[11] << 8) | data[12]);
        out->pressure = pressure;
        out->temperature = temperature;
        out->frameType = L"env";
        return;
    }
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

// Parse additional config keys from PortSniffer-Tool.config
static void TryReadAgentConfig(void)
{
    WCHAR wszUrl[1024];
    if (TryReadDefaultForwardUrl(wszUrl, _countof(wszUrl))) {
        // already read by caller when needed
    }

    // Same config file parsing as TryReadDefaultForwardUrl: simple key=value lines
    WCHAR wszExePath[MAX_PATH], wszDir[MAX_PATH], wszCfgPath[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, wszExePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return;
    wcscpy_s(wszDir, MAX_PATH, wszExePath);
    WCHAR* p = wcsrchr(wszDir, L'\\');
    if (!p) return; *p = L'\0';
    if (FAILED(StringCchPrintfW(wszCfgPath, MAX_PATH, L"%s\\PortSniffer-Tool.config", wszDir))) return;

    HANDLE h = CreateFileW(wszCfgPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    BYTE buf[2048]; DWORD cbRead = 0; BOOL ok = ReadFile(h, buf, sizeof(buf) - 2, &cbRead, NULL); CloseHandle(h);
    if (!ok || cbRead == 0) return; buf[cbRead] = '\0'; buf[cbRead + 1] = '\0';

    const char* line = (const char*)buf; const char* end; const char* start = line;
    while (*line) {
        while (*line == '\r' || *line == '\n') line++;
        if (!*line) break;
        end = line; while (*end && *end != '\r' && *end != '\n') end++;
        // Keys: aggregate_ms=INT, decoder_profile=raw|texno_uz|texno_uz_alt1, crc_required=true|false
        if (_strnicmp(line, "aggregate_ms=", 13) == 0) {
            int v = atoi(line + 13);
            if (v >= 5 && v <= 2000) gAggregateGapMs = (DWORD)v;
        } else if (_strnicmp(line, "decoder_profile=", 16) == 0) {
            const char* val = line + 16;
            if (_strnicmp(val, "raw", 3) == 0) gDecoderProfile = DECODER_RAW;
            else if (_strnicmp(val, "texno_uz_alt1", 13) == 0) gDecoderProfile = DECODER_TEXNO_UZ_ALT1;
            else gDecoderProfile = DECODER_TEXNO_UZ; // default
        } else if (_strnicmp(line, "crc_required=", 13) == 0) {
            const char* val = line + 13;
            gCrcRequired = (_strnicmp(val, "true", 4) == 0 || _strnicmp(val, "1", 1) == 0 || _strnicmp(val, "yes", 3) == 0);
        }
        line = (*end ? end + 1 : end);
    }
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

    // Try to decode Texno UZ
    TEXNO_DECODE d; _DecodeTexno(pEntry->Data, pEntry->DataLength, &d);

    if (d.isTexno)
    {
        // Build enriched JSON with parsed fields
        if (wcscmp(d.frameType, L"flow") == 0)
        {
            StringCchPrintfW(json, _countof(json),
                L"{\"port\":\"%s\",\"timestamp\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\",\"type\":%u,\"length\":%u,\"data_hex\":\"%s\",\"proto\":\"texno_uz\",\"device_id\":%d,\"crc_ok\":%s,\"frame_type\":\"flow\",\"volume_l\":%.2f,\"amount\":%lu}",
                pwszPort,
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                (unsigned)pEntry->Type,
                (unsigned)pEntry->DataLength,
                wszHex,
                d.deviceId,
                d.crcOk ? L"true" : L"false",
                d.volumeLiters,
                d.amount);
        }
        else if (wcscmp(d.frameType, L"env") == 0)
        {
            StringCchPrintfW(json, _countof(json),
                L"{\"port\":\"%s\",\"timestamp\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\",\"type\":%u,\"length\":%u,\"data_hex\":\"%s\",\"proto\":\"texno_uz\",\"device_id\":%d,\"crc_ok\":%s,\"frame_type\":\"env\",\"pressure\":%d,\"temperature\":%d}",
                pwszPort,
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                (unsigned)pEntry->Type,
                (unsigned)pEntry->DataLength,
                wszHex,
                d.deviceId,
                d.crcOk ? L"true" : L"false",
                d.pressure,
                d.temperature);
        }
        else
        {
            StringCchPrintfW(json, _countof(json),
                L"{\"port\":\"%s\",\"timestamp\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\",\"type\":%u,\"length\":%u,\"data_hex\":\"%s\",\"proto\":\"texno_uz\",\"device_id\":%d,\"crc_ok\":%s,\"frame_type\":\"unknown\"}",
                pwszPort,
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                (unsigned)pEntry->Type,
                (unsigned)pEntry->DataLength,
                wszHex,
 
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

    // Determine forward URL (CLI or config); also load agent config (aggregate_ms, decoder_profile, crc_required)
    wszForward[0] = L'\0';
    TryReadAgentConfig();
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
    // Per-port pending aggregates
    PENDING_AGGREGATE pending[MAX_MONITORING_PORTS];
    ZeroMemory(pending, sizeof(pending));

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

            // Aggregate logic: same port and type, within gap, append; else flush
            PENDING_AGGREGATE* agg = &pending[iPortIdx];
            BOOL shouldFlush = FALSE;
            if (!agg->hasData)
            {
                agg->hasData = TRUE;
                agg->type = pPopResponse->Type;
                agg->lastTimestamp = pPopResponse->Timestamp;
                agg->length = 0;
            }
            else
            {
                // Check type change
                if (agg->type != pPopResponse->Type)
                {
                    shouldFlush = TRUE;
                }
                else
                {
                    // Check time gap
                    LONGLONG prev = agg->lastTimestamp.QuadPart;
                    LONGLONG curr = pPopResponse->Timestamp.QuadPart;
                    // FILETIME ticks (100 ns). Convert to ms diff.
                    LONGLONG diffMs = (curr - prev) / 10000;
                    if (diffMs > (LONGLONG)gAggregateGapMs)
                        shouldFlush = TRUE;
                }
            }

            if (shouldFlush)
            {
                // Flush current aggregate
                PORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE out;
                ZeroMemory(&out, sizeof(out));
                out.Type = agg->type;
                out.DataLength = agg->length;
                out.Timestamp = agg->lastTimestamp; // last packet ts; UI shows increasing ts anyway
                memcpy(out.Data, agg->data, agg->length);

                if (!_PrintResponse(&out, PopRequest[iPortIdx].PortName)) goto Cleanup;
                if (wszForward[0] != L'\0') SendLogEntryToApi(wszForward, PopRequest[iPortIdx].PortName, &out);

                // Reset for new sequence
                agg->hasData = TRUE;
                agg->type = pPopResponse->Type;
                agg->lastTimestamp = pPopResponse->Timestamp;
                agg->length = 0;
            }

            // Append current chunk
            {
                size_t canCopy = pPopResponse->DataLength;
                if (agg->length + canCopy > AGGREGATE_MAX_BYTES)
                {
                    canCopy = AGGREGATE_MAX_BYTES - agg->length;
                }
                if (canCopy > 0)
                {
                    memcpy(agg->data + agg->length, pPopResponse->Data, canCopy);
                    agg->length = (USHORT)(agg->length + (USHORT)canCopy);
                }
                agg->lastTimestamp = pPopResponse->Timestamp;
            }
        }

        if (noMore == nPortCount)
        {
            Sleep(10);
        }
    }

    // Final flush for all ports
    for (iPortIdx = 0; iPortIdx < nPortCount; iPortIdx++)
    {
        PENDING_AGGREGATE* agg = &pending[iPortIdx];
        if (agg->hasData && agg->length > 0)
        {
            PORTSNIFFER_POP_PORTLOG_ENTRY_RESPONSE out;
            ZeroMemory(&out, sizeof(out));
            out.Type = agg->type;
            out.DataLength = agg->length;
            out.Timestamp = agg->lastTimestamp;
            memcpy(out.Data, agg->data, agg->length);
            _PrintResponse(&out, PopRequest[iPortIdx].PortName);
            if (wszForward[0] != L'\0') SendLogEntryToApi(wszForward, PopRequest[iPortIdx].PortName, &out);
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
