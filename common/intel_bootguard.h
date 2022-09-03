/* intel_bootguard.h

Copyright (c) 2021, Nikolaj Schlej. All rights reserved.
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

*/

#ifndef INTEL_BOOTGUARD_H
#define INTEL_BOOTGUARD_H

#include "basetypes.h"

#pragma pack(push, 1)

//
// Intel ACM
//

#define INTEL_ACM_MODULE_TYPE               0x2
#define INTEL_ACM_MODULE_SUBTYPE_TXT_ACM    0x0
#define INTEL_ACM_MODULE_SUBTYPE_S_ACM      0x1
#define INTEL_ACM_MODULE_SUBTYPE_BOOTGUARD  0x3
#define INTEL_ACM_MODULE_VENDOR             0x8086

typedef struct INTEL_ACM_HEADER_ {
    UINT16 ModuleType;
    UINT16 ModuleSubtype;
    UINT32 HeaderType;
    UINT32 HeaderVersion;
    UINT16 ChipsetId;
    UINT16 Flags;
    UINT32 ModuleVendor;
    UINT8  DateDay;
    UINT8  DateMonth;
    UINT16 DateYear;
    UINT32 ModuleSize;
    UINT16 AcmSvn;
    UINT16 SeSvn;
    UINT32 CodeControlFlags;
    UINT32 ErrorEntryPoint;
    UINT32 GdtMax;
    UINT32 GdtBase;
    UINT32 SegmentSel;
    UINT32 EntryPoint;
    UINT8  Reserved[64];
    UINT32 KeySize;
    UINT32 ScratchSpaceSize;
    UINT8  RsaPubKey[256];
    UINT32 RsaPubExp;
    UINT8  RsaSig[256];
} INTEL_ACM_HEADER;

//
// Intel BootGuard Key Manifest
//
#define BG_BOOT_POLICY_MANIFEST_HEADER_TAG (*(UINT64 *)"__ACBP__")
typedef struct INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER_ {
    UINT64 Tag;
    UINT8  Version;
    UINT8  HeaderVersion;
    UINT8  PMBPMVersion;
    UINT8  BPSVN;
    UINT8  ACMSVN;
    UINT8  : 8;
    UINT16 NEMDataSize;
} INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER;

#define INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_VERSION_10 0x10
#define INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_VERSION_1F 0x1F

typedef struct INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER2_ {
    UINT64 Tag;
    UINT8  Version;
    UINT8  HeaderVersion;
    UINT16 HeaderSize;
    UINT16 RSAEntryOffset;
    UINT8  PMBPMVersion;
    UINT8  BPSVN;
    UINT8  ACMSVN;
    UINT8  : 8;
    UINT16 NEMDataSize;
} INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER2;

#define INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_VERSION_20 0x20
#define INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_VERSION_2F 0x2F

typedef struct INTEL_BOOT_GUARD_SHA256_HASH_ {
    UINT16 HashAlgorithmId;
    UINT16 Size;
    UINT8  HashBuffer[32];
} INTEL_BOOT_GUARD_HASH_SHA256;

typedef struct INTEL_BOOT_GUARD_HASH_HEADER_ {
    UINT16 HashAlgorithmId;
    UINT16 Size;
} INTEL_BOOT_GUARD_HASH_HEADER;

#define INTEL_BOOT_GUARD_HASH_ALGORITHM_SHA1   0x0004
#define INTEL_BOOT_GUARD_HASH_ALGORITHM_SHA256 0x000B
#define INTEL_BOOT_GUARD_HASH_ALGORITHM_SHA384 0x000C

typedef struct INTEL_BOOT_GUARD_RSA_PUBLIC_KEY_ {
    UINT8  Version;
    UINT16 KeySize;
    UINT32 Exponent;
    UINT8  Modulus[256];
} INTEL_BOOT_GUARD_RSA_PUBLIC_KEY;

typedef struct INTEL_BOOT_GUARD_RSA_SIGNATURE_ {
    UINT8  Version;
    UINT16 KeySize;
    UINT16 HashId;
    UINT8  Signature[256];
} INTEL_BOOT_GUARD_RSA_SIGNATURE;

typedef struct INTEL_BOOT_GUARD_KEY_SIGNATURE_ {
    UINT8                           Version;
    UINT16                          KeyId;
    INTEL_BOOT_GUARD_RSA_PUBLIC_KEY PubKey;
    UINT16                          SigScheme;
    INTEL_BOOT_GUARD_RSA_SIGNATURE  Signature;
} INTEL_BOOT_GUARD_KEY_SIGNATURE;

#define INTEL_BOOT_GUARD_IBB_SEGMENT_FLAG_IBB      0x0
#define INTEL_BOOT_GUARD_IBB_SEGMENT_FLAG_NON_IBB  0x1
typedef struct INTEL_BOOT_GUARD_IBB_SEGMENT_ELEMENT_ {
    UINT16 : 16;
    UINT16 Flags;
    UINT32 Base;
    UINT32 Size;
} INTEL_BOOT_GUARD_IBB_SEGMENT_ELEMENT;

#define INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_IBB_ELEMENT_TAG  (*(UINT64 *)"__IBBS__")
#define INTEL_BOOT_GUARD_IBB_FLAG_AUTHORITY_MEASURE            0x4

typedef struct INTEL_BOOT_GUARD_IBB_ELEMENT_ {
    UINT64                       Tag;
    UINT8                        Version;
    UINT8                        : 8;
    UINT8                        : 8;
    UINT8                        : 8;
    UINT32                       Flags;
    UINT64                       IbbMchBar;
    UINT64                       VtdBar;
    UINT32                       PmrlBase;
    UINT32                       PmrlLimit;
    UINT64                       : 64;
    UINT64                       : 64;
    INTEL_BOOT_GUARD_HASH_SHA256 IbbHash;
    UINT32                       EntryPoint;
    INTEL_BOOT_GUARD_HASH_SHA256 Digest;
    UINT8                        IbbSegCount;
    // INTEL_BOOT_GUARD_IBB_SEGMENT_ELEMENT IbbSegment[];
} INTEL_BOOT_GUARD_IBB_ELEMENT;

typedef struct INTEL_BOOT_GUARD_IBB_ELEMENT2_ {
    UINT64                 Tag;
    UINT16                 Version;
    UINT16                 ElementSize;
    UINT8                  : 8;
    UINT8                  : 8;
    UINT8                  : 8;
    UINT8                  PolicyTimerVal;
    UINT32                 Flags;
    UINT64                 IbbMchBar;
    UINT64                 VtdBar;
    UINT32                 PmrlBase;
    UINT32                 PmrlLimit;
    UINT64                 : 64;
    UINT64                 : 64;
    UINT32                 PostIbbHash;
    UINT32                 EntryPoint;
    UINT16                 SizeOfDigests;
    UINT16                 NumOfDigests;
    //UINT8                Digests[];
} INTEL_BOOT_GUARD_IBB_ELEMENT2;

#define INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_PLATFORM_MANUFACTURER_ELEMENT_TAG  (*(UINT64 *)"__PMDA__")
typedef struct INTEL_BOOT_GUARD_PLATFORM_MANUFACTURER_ELEMENT_ {
    UINT64 Tag;
    UINT8  Version;
    UINT16 DataSize;
} INTEL_BOOT_GUARD_PLATFORM_MANUFACTURER_ELEMENT;

typedef struct INTEL_BOOT_GUARD_MICROSOFT_PMDA_HEADER_ {
    UINT32 Version;
    UINT32 NumEntries;
} INTEL_BOOT_GUARD_MICROSOFT_PMDA_HEADER;

#define INTEL_BOOT_GUARD_MICROSOFT_PMDA_VERSION 0x00000001

typedef struct INTEL_BOOT_GUARD_MICROSOFT_PMDA_ENTRY_ {
    UINT32 Address;
    UINT32 Size;
    UINT8  Hash[SHA256_HASH_SIZE];
} INTEL_BOOT_GUARD_MICROSOFT_PMDA_ENTRY;

#define INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT_TAG  (*(UINT64 *)"__PMSG__")
typedef struct INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT_ {
    UINT64               Tag;
    UINT8                Version;
    INTEL_BOOT_GUARD_KEY_SIGNATURE     KeySignature;
} INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT;

typedef struct INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT2_ {
    UINT64               Tag;
    UINT8                Version;
    UINT8                Unknown[3];
    INTEL_BOOT_GUARD_KEY_SIGNATURE     KeySignature;
} INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT2;

#define INTEL_BOOT_GUARD_KEY_MANIFEST_TAG  (*(UINT64 *)"__KEYM__")
typedef struct INTEL_BOOT_GUARD_KEY_MANIFEST_ {
    UINT64                         Tag;
    UINT8                          Version;
    UINT8                          KmVersion;
    UINT8                          KmSvn;
    UINT8                          KmId;
    INTEL_BOOT_GUARD_HASH_SHA256   BpKeyHash;
    INTEL_BOOT_GUARD_KEY_SIGNATURE KeyManifestSignature;
} INTEL_BOOT_GUARD_KEY_MANIFEST;

#define INTEL_BOOT_GUARD_KEY_MANIFEST_VERSION_10 0x10
#define INTEL_BOOT_GUARD_KEY_MANIFEST_VERSION_1F 0x1F

typedef struct INTEL_BOOT_GUARD_KEY_MANIFEST2_ {
    UINT64                           Tag;
    UINT8                            Version;
    UINT8                            ReservedZero1[3];
    UINT32                           SignatureOffset;
    UINT8                            ReservedZero2;
    UINT8                            KmVersion;
    UINT8                            KmSvn;
    UINT8                            KmId;
    UINT16                           HashAlgorithmId;
    UINT16                           TotalKeys;
    UINT64                           Reserved; // Seen 0x01
    //INTEL_BOOT_GUARD_HASH          BpKeyHash;
    //INTEL_BOOT_GUARD_KEY_SIGNATURE KeyManifestSignature;
} INTEL_BOOT_GUARD_KEY_MANIFEST2;

#define INTEL_BOOT_GUARD_KEY_MANIFEST_VERSION_20 0x20
#define INTEL_BOOT_GUARD_KEY_MANIFEST_VERSION_2F 0x2F

#pragma pack(pop)

#endif // INTEL_BOOTGUARD_H
