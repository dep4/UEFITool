/* intel_fit.h

Copyright (c) 2015, Nikolaj Schlej. All rights reserved.
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHWARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
*/

#ifndef INTEL_FIT_H
#define INTEL_FIT_H

#include "basetypes.h"
#include "ubytearray.h"

// Make sure we use right packing rules
#pragma pack(push, 1)

// Memory address of a pointer to FIT, 40h back from the end of flash chip
#define INTEL_FIT_POINTER_OFFSET 0x40

// Entry types
// https://www.intel.com/content/dam/develop/external/us/en/documents/firmware-interface-table-bios-specification-r1p2p1.pdf
#define INTEL_FIT_TYPE_HEADER              0x00
#define INTEL_FIT_TYPE_MICROCODE           0x01
#define INTEL_FIT_TYPE_BIOS_AC_MODULE      0x02
#define INTEL_FIT_TYPE_DIAG_AC_MODULE      0x03
#define INTEL_FIT_TYPE_BIOS_STARTUP_MODULE 0x07
#define INTEL_FIT_TYPE_TPM_POLICY          0x08
#define INTEL_FIT_TYPE_BIOS_POLICY_DATA    0x09
#define INTEL_FIT_TYPE_TXT_CONF_POLICY     0x0A
#define INTEL_FIT_TYPE_AC_KEY_MANIFEST     0x0B
#define INTEL_FIT_TYPE_AC_BOOT_POLICY      0x0C
#define INTEL_FIT_TYPE_CSE_SECURE_BOOT     0x10
#define INTEL_FIT_TYPE_TXTSX_POLICY        0x2D
#define INTEL_FIT_TYPE_JMP_DEBUG_POLICY    0x2F
#define INTEL_FIT_TYPE_EMPTY               0x7F

#define INTEL_FIT_HEADER_VERSION         0x0100
#define INTEL_FIT_MICROCODE_VERSION      0x0100

const UByteArray INTEL_FIT_SIGNATURE
("\x5F\x46\x49\x54\x5F\x20\x20\x20", 8);

typedef struct INTEL_FIT_ENTRY_ {
    UINT64 Address;
    UINT32 Size : 24;
    UINT32 : 8;
    UINT16 Version;
    UINT8  Type : 7;
    UINT8  CsFlag : 1;
    UINT8  Checksum;
} INTEL_FIT_ENTRY;

typedef struct INTEL_FIT_ENTRY_VERSION_0_CONFIG_POLICY_ {
    UINT16 IndexRegisterAddress;
    UINT16 DataRegisterAddress;
    UINT8  AccessWidth;
    UINT8  BitPosition;
    UINT16 Index;
} INTEL_FIT_ENTRY_VERSION_0_CONFIG_POLICY;

#pragma pack(pop)

#endif // INTEL_FIT_H
