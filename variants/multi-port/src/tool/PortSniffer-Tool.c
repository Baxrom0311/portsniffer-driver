//
// PortSniffer - Monitor the traffic of arbitrary serial or parallel ports
// Copyright 2020-2022 Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>
//
// SPDX-License-Identifier: MIT
//

#include <initguid.h>
#include "PortSniffer-Tool.h"


static int
_PrintUsage()
{
    printf("Usage: PortSniffer-Tool [OPTIONS]\n");
    printf("\n");
    printf("Installation Options:\n");
    printf("    /install                Install the driver.\n");
    printf("    /uninstall              Uninstall the driver.\n");
    printf("\n");
    printf("Setup Options:\n");
    printf("    /ports                  Get all ports that can be monitored.\n");
    printf("    /attached               Get all ports the driver is currently attached to.\n");
    printf("    /attach PORT            Attach the driver to the given port.\n");
    printf("    /detach PORT            Detach the driver from the given port.\n");
    printf("    /attachAll              Attach the driver to ALL monitorable ports.\n");
    printf("    /detachAll              Detach the driver from ALL monitorable ports.\n");
    printf("    /version                Get the version of the running driver.\n");
    printf("\n");
    printf("Monitoring:\n");
    printf("    /monitor PORT1 [PORT2 ...] TYPES [/forward URL]\n");
    printf("                            Monitor the given port(s). Optionally forward entries to URL.\n");
    printf("                            TYPES may be one or more of:\n");
    printf("                               R - Read requests\n");
    printf("                               W - Write requests\n");
    printf("                               C - IOCTL_SERIAL_* requests\n");
    printf("\n");

    return 1;
}

static BOOL
_ContainsForwardToken(
    wchar_t* argv[],
    int startIndex,
    int endIndex
    )
{
    int i;

    for (i = startIndex; i < endIndex; ++i)
    {
        if (_wcsicmp(argv[i], L"/forward") == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

HANDLE
OpenPortSniffer(void)
{
    HANDLE hPortSniffer;

    hPortSniffer = CreateFileW(L"\\\\.\\EnlyzePortSniffer", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPortSniffer == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "Could not open \"\\\\.\\EnlyzePortSniffer\", last error is %lu.\n", GetLastError());
        fprintf(stderr, "This can have various reasons:\n");
        fprintf(stderr, "- The PortSniffer Driver is not installed\n");
        fprintf(stderr, "- The PortSniffer Driver is not attached to any port\n");
        fprintf(stderr, "- You have not turned off Driver Signature Enforcement at boot\n");
    }

    return hPortSniffer;
}

int __cdecl
wmain(
    int argc,
    wchar_t* argv[]
    )
{
    setbuf(stdout, NULL);
    printf("**********************************************************************\n");
    printf("ENLYZE PortSniffer Tool " PORTSNIFFER_VERSION_COMBINED "\n");
    printf("Copyright " COPYRIGHT_YEAR_STRING " Colin Finck, ENLYZE GmbH <c.finck@enlyze.com>\n");
    printf("**********************************************************************\n\n");

    if (argc == 2 && wcscmp(argv[1], L"/install") == 0)
    {
        return HandleInstallParameter();
    }
    else if (argc == 2 && wcscmp(argv[1], L"/uninstall") == 0)
    {
        return HandleUninstallParameter();
    }
    else if (argc == 2 && wcscmp(argv[1], L"/ports") == 0)
    {
        return HandlePortsParameter();
    }
    else if (argc == 2 && wcscmp(argv[1], L"/attached") == 0)
    {
        return HandleAttachedParameter();
    }
    else if (argc == 3 && wcscmp(argv[1], L"/attach") == 0)
    {
        return HandleAttachParameter(argv[2]);
    }
    else if (argc == 3 && wcscmp(argv[1], L"/detach") == 0)
    {
        return HandleDetachParameter(argv[2]);
    }
    else if (argc == 2 && wcscmp(argv[1], L"/attachAll") == 0)
    {
        return HandleAttachAllParameter();
    }
    else if (argc == 2 && wcscmp(argv[1], L"/detachAll") == 0)
    {
        return HandleDetachAllParameter();
    }
    else if (argc == 2 && wcscmp(argv[1], L"/version") == 0)
    {
        return HandleVersionParameter();
    }
    else if (argc >= 2 && wcscmp(argv[1], L"/monitor") == 0)
    {
        // Find optional /forward URL segment at the end
        PCWSTR pwszForward = NULL;
        int typesIndex;
        int firstPortIndex = 2;
        int lastMonitorArg = argc - 1;

        if (argc < 4)
        {
            return _PrintUsage();
        }

        if (argc >= 6 && _wcsicmp(argv[argc - 2], L"/forward") == 0)
        {
            pwszForward = argv[argc - 1];
            lastMonitorArg = argc - 3;

            if (_ContainsForwardToken(argv, firstPortIndex, argc - 2))
            {
                return _PrintUsage();
            }
        }
        else if (_ContainsForwardToken(argv, firstPortIndex, argc))
        {
            return _PrintUsage();
        }

        // TYPES is the last argument in the remaining range
        typesIndex = lastMonitorArg;
        if (typesIndex <= firstPortIndex)
        {
            return _PrintUsage();
        }

        // Pass the list of ports [argv[2]..argv[typesIndex-1]] and TYPES
        return HandleMonitorParameterMulti(&argv[firstPortIndex], typesIndex - firstPortIndex, argv[typesIndex], pwszForward);
    }
    else
    {
        return _PrintUsage();
    }
}
