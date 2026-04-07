/*
 * test_wcslen_fix.c
 * Tests the critical wcslen bug fix in multi-SZ string iteration.
 *
 * BUG:   for (p = PortNames; *p; p += wcslen(PortNames) + 1)  // always uses first string length
 * FIX:   for (p = PortNames; *p; p += wcslen(p) + 1)          // uses current string length
 *
 * Compile: gcc -o test_wcslen_fix.exe test_wcslen_fix.c
 */
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <stdlib.h>

/* Simulate a REG_MULTI_SZ buffer where the FIRST port is SHORTER than the others.
 * This is the case that exposes the bug — wcslen(PortNames) returns the length
 * of the FIRST string, so subsequent strides are too small and land mid-string.
 */
static wchar_t g_PortNames[] = L"COM\0COMPORT5\0COMPORT10\0";

static int test_count = 0;
static int pass_count = 0;

static void check(int cond, const char* name) {
    test_count++;
    if (cond) {
        pass_count++;
        printf("  [PASS] %s\n", name);
    } else {
        printf("  [FAIL] %s\n", name);
    }
}

/* ---- BUGGY version (old code) ---- */
static int iterate_buggy(wchar_t* PortNames, wchar_t** out, int max) {
    const wchar_t* p;
    int count = 0;
    for (p = PortNames; *p; p += wcslen(PortNames) + 1) {
        if (count < max) {
            out[count] = (wchar_t*)p;
        }
        count++;
        if (count > 100) {  /* safety: prevent infinite loop */
            printf("  [WARN] Buggy loop ran >100 iterations - breaking\n");
            break;
        }
    }
    return count;
}

/* ---- FIXED version (new code) ---- */
static int iterate_fixed(wchar_t* PortNames, wchar_t** out, int max) {
    const wchar_t* p;
    int count = 0;
    for (p = PortNames; *p; p += wcslen(p) + 1) {
        if (count < max) {
            out[count] = (wchar_t*)p;
        }
        count++;
    }
    return count;
}

int main(void) {
    wchar_t* results[10];
    int count;

    printf("============================================\n");
    printf("  PortSniffer wcslen() Bug Fix Test\n");
    printf("============================================\n\n");

    /* The test buffer: "COM\0COMPORT5\0COMPORT10\0\0" — first port is shortest */
    printf("Test buffer: \"COM\\0COMPORT5\\0COMPORT10\\0\\0\"\n");
    printf("Expected: 3 ports - COM, COMPORT5, COMPORT10\n\n");

    /* ---- Test 1: Buggy version ---- */
    printf("--- Test 1: BUGGY version (wcslen(PortNames)) ---\n");
    memset(results, 0, sizeof(results));
    count = iterate_buggy(g_PortNames, results, 10);
    printf("  Found %d port(s)\n", count);

    if (count >= 1) printf("  Port[0]: %ls\n", results[0]);
    if (count >= 2) printf("  Port[1]: %ls\n", results[1]);
    if (count >= 3) printf("  Port[2]: %ls\n", results[2]);

    /* The buggy version uses wcslen("COM") = 3 every time, so stride = 4.
     * Step 1: p = PortNames+0 -> "COM"      (OK)
     * Step 2: p = PortNames+4 -> "COMPORT5" -> length 8, but next stride still 4
     * Step 3: p = PortNames+8 -> "RT5\0..." -> reads "RT5" (WRONG!)
     */
    if (count >= 1) check(wcscmp(results[0], L"COM") == 0, "Buggy: port[0] is COM (always works)");
    if (count >= 2) check(wcscmp(results[1], L"COMPORT5") == 0, "Buggy: port[1] is COMPORT5 (accidentally OK)");
    if (count >= 3) check(wcscmp(results[2], L"COMPORT10") != 0, "Buggy: port[2] is NOT COMPORT10 (reads garbage)");

    printf("\n");

    /* ---- Test 2: Fixed version ---- */
    printf("--- Test 2: FIXED version (wcslen(p)) ---\n");
    memset(results, 0, sizeof(results));
    count = iterate_fixed(g_PortNames, results, 10);
    printf("  Found %d port(s)\n", count);

    if (count >= 1) printf("  Port[0]: %ls\n", results[0]);
    if (count >= 2) printf("  Port[1]: %ls\n", results[1]);
    if (count >= 3) printf("  Port[2]: %ls\n", results[2]);

    check(count == 3, "Fixed version finds exactly 3 ports");
    check(count >= 1 && wcscmp(results[0], L"COM") == 0, "Fixed: port[0] == COM");
    check(count >= 2 && wcscmp(results[1], L"COMPORT5") == 0, "Fixed: port[1] == COMPORT5");
    check(count >= 3 && wcscmp(results[2], L"COMPORT10") == 0, "Fixed: port[2] == COMPORT10");

    printf("\n");

    /* ---- Test 3: Single port (both should work) ---- */
    printf("--- Test 3: Single port (edge case) ---\n");
    {
        wchar_t single[] = L"COM1\0";
        int c_bug, c_fix;
        wchar_t* r1[10] = {0};
        wchar_t* r2[10] = {0};

        c_bug = iterate_buggy(single, r1, 10);
        c_fix = iterate_fixed(single, r2, 10);

        printf("  Buggy: %d port(s), Fixed: %d port(s)\n", c_bug, c_fix);
        check(c_bug == 1 && c_fix == 1, "Both find exactly 1 port with single entry");
        check(c_bug >= 1 && wcscmp(r1[0], L"COM1") == 0, "Buggy: single port OK");
        check(c_fix >= 1 && wcscmp(r2[0], L"COM1") == 0, "Fixed: single port OK");
    }

    printf("\n");

    /* ---- Test 4: Equal length ports ---- */
    printf("--- Test 4: Equal length ports ---\n");
    {
        wchar_t equal[] = L"COM1\0COM2\0COM3\0";
        int c_bug, c_fix;
        wchar_t* r1[10] = {0};
        wchar_t* r2[10] = {0};

        c_bug = iterate_buggy(equal, r1, 10);
        c_fix = iterate_fixed(equal, r2, 10);

        printf("  Buffer: \"COM1\\0COM2\\0COM3\\0\\0\"\n");
        printf("  Buggy: %d port(s), Fixed: %d port(s)\n", c_bug, c_fix);

        /* When all strings have equal length, the buggy version accidentally works! */
        check(c_bug == 3, "Buggy: works with equal-length strings (accidental)");
        check(c_fix == 3, "Fixed: works with equal-length strings");
    }

    printf("\n============================================\n");
    printf("  Results: %d / %d tests passed\n", pass_count, test_count);
    printf("============================================\n");

    return (pass_count == test_count) ? 0 : 1;
}
