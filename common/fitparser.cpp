#include "fitparser.h"
#include "intel_fit.h"
#include "ffs.h"
#include "parsingdata.h"
#include "types.h"
#include "utility.h"
#include "sha256.h"

USTATUS FitParser::parseFit(const UModelIndex & index)
{
    // Reset parser state
    fitTable.clear();
    securityInfo = "";
    bgAcmFound = false;
    bgKeyManifestFound = false;
    bgBootPolicyFound = false;
    bgAcmFound = false;
    bgKeyManifestFound = false;
    bgBootPolicyFound = false;
    bgKmHash = UByteArray();
    bgBpHash = UByteArray();
    bgBpDigest = UByteArray();
    
    // Check sanity
    if (!index.isValid()) {
        return U_INVALID_PARAMETER;
    }
    
    // Search for FIT
    UModelIndex fitIndex;
    UINT32 fitOffset;
    findFitRecursive(index, fitIndex, fitOffset);
    
    // FIT not found
    if (!fitIndex.isValid()) {
        // Nothing to parse further
        return U_SUCCESS;
    }
    // Explicitly set the item containing FIT as fixed
    model->setFixed(fitIndex, true);
    
    // Special case of FIT header
    UByteArray fitBody = model->body(fitIndex);
    const INTEL_FIT_ENTRY* fitHeader = (const INTEL_FIT_ENTRY*)(fitBody.constData() + fitOffset);
    
    // Check FIT checksum, if present
    UINT32 fitSize = fitHeader->Size * sizeof(INTEL_FIT_ENTRY);
    if (fitHeader->ChecksumValid) {
        // Calculate FIT entry checksum
        UByteArray tempFIT = model->body(fitIndex).mid(fitOffset, fitSize);
        INTEL_FIT_ENTRY* tempFitHeader = (INTEL_FIT_ENTRY*)tempFIT.data();
        tempFitHeader->Checksum = 0;
        UINT8 calculated = calculateChecksum8((const UINT8*)tempFitHeader, fitSize);
        if (calculated != fitHeader->Checksum) {
            msg(usprintf("%s: invalid FIT table checksum %02Xh, should be %02Xh", __FUNCTION__, fitHeader->Checksum, calculated), fitIndex);
        }
    }
    
    // Check fit header type
    if (fitHeader->Type != INTEL_FIT_TYPE_HEADER) {
        msg(usprintf("%s: invalid FIT header type", __FUNCTION__), fitIndex);
        return U_INVALID_FIT;
    }
    
    // Add FIT header
    std::vector<UString> currentStrings;
    currentStrings.push_back(UString("_FIT_            "));
    currentStrings.push_back(usprintf("%08Xh", fitSize));
    currentStrings.push_back(usprintf("%04Xh", fitHeader->Version));
    currentStrings.push_back(usprintf("%02Xh", fitHeader->Checksum));
    currentStrings.push_back(fitEntryTypeToUString(fitHeader->Type));
    currentStrings.push_back(UString()); // Empty info for FIT header
    fitTable.push_back(std::pair<std::vector<UString>, UModelIndex>(currentStrings, fitIndex));
    
    // Process all other entries
    UModelIndex startupAcmIndex;
    UModelIndex kmIndex;
    UModelIndex bpIndex;
    for (UINT32 i = 1; i < fitHeader->Size; i++) {
        currentStrings.clear();
        UString info;
        UModelIndex itemIndex;
        const INTEL_FIT_ENTRY* currentEntry = fitHeader + i;
        UINT32 currentEntrySize = currentEntry->Size;
        
        // Check sanity
        if (currentEntry->Type == INTEL_FIT_TYPE_HEADER) {
            msg(usprintf("%s: second FIT header found, the table is damaged", __FUNCTION__), fitIndex);
            return U_INVALID_FIT;
        }
        
        //TODO: limit this to entry types that can have IndexIo addressing
        // Special case of version 0 entries
        if (currentEntry->Version == 0) {
            const INTEL_FIT_INDEX_IO_ADDRESS* policy = (const INTEL_FIT_INDEX_IO_ADDRESS*)currentEntry;
            info += usprintf("Index: %04Xh BitPosition: %02Xh AccessWidth: %02Xh DataRegAddr: %04Xh IndexRegAddr: %04Xh",
                             policy->Index,
                             policy->BitPosition,
                             policy->AccessWidthInBytes,
                             policy->DataRegisterAddress,
                             policy->IndexRegisterAddress);
        }
        else if (currentEntry->Address > ffsParser->addressDiff && currentEntry->Address < 0xFFFFFFFFUL) { // Only elements in the image need to be parsed
            UINT32 currentEntryBase = (UINT32)(currentEntry->Address - ffsParser->addressDiff);
            itemIndex = model->findByBase(currentEntryBase);
            if (itemIndex.isValid()) {
                USTATUS status = U_INVALID_FIT;
                UByteArray item = model->header(itemIndex) + model->body(itemIndex) + model->tail(itemIndex);
                UINT32 localOffset = currentEntryBase - model->base(itemIndex);
                
                switch (currentEntry->Type) {
                    case INTEL_FIT_TYPE_MICROCODE:
                        status = parseFitEntryMicrocode(item, localOffset, itemIndex, info, currentEntrySize);
                        break;
                        
                    case INTEL_FIT_TYPE_STARTUP_AC_MODULE:
                        status = parseFitEntryAcm(item, localOffset, itemIndex, info, currentEntrySize);
                        startupAcmIndex = itemIndex;
                        break;
                        
                    case INTEL_FIT_TYPE_BOOT_GUARD_KEY_MANIFEST:
                        status = parseFitEntryBootGuardKeyManifest(item, localOffset, itemIndex, info, currentEntrySize);
                        kmIndex = itemIndex;
                        break;
                        
                    case INTEL_FIT_TYPE_BOOT_GUARD_BOOT_POLICY:
                        status = parseFitEntryBootGuardBootPolicy(item, localOffset, itemIndex, info, currentEntrySize);
                        bpIndex = itemIndex;
                        break;
                        
                    default:
                        // Do nothing
                        status = U_SUCCESS;
                        break;
                }
                
                // Make sure that the resulting itemIndex is not valid in case of any parsing errors
                if (status != U_SUCCESS) {
                    itemIndex = UModelIndex();
                }
            }
            else {
                msg(usprintf("%s: FIT entry #%u not found in the image", __FUNCTION__, i), fitIndex);
            }
        }
        
        // Explicitly set the item referenced by FIT as fixed
        // TODO: lift this restriction after FIT builder is ready
        if (itemIndex.isValid()) {
            model->setFixed(itemIndex, true);
        }
        
        // Add entry to fitTable
        currentStrings.push_back(usprintf("%016" PRIX64 "h", currentEntry->Address));
        currentStrings.push_back(usprintf("%08Xh", currentEntrySize));
        currentStrings.push_back(usprintf("%04Xh", currentEntry->Version));
        currentStrings.push_back(usprintf("%02Xh", currentEntry->Checksum));
        currentStrings.push_back(fitEntryTypeToUString(currentEntry->Type));
        currentStrings.push_back(info);
        fitTable.push_back(std::pair<std::vector<UString>, UModelIndex>(currentStrings, itemIndex));
    }
    
// TODO: properly reenable when BG2 parsers are ready
#if 0 //Disable for now
    // Perform validation of BootGuard stuff
    if (bgAcmFound) {
        if (!bgKeyManifestFound) {
            msg(usprintf("%s: startup ACM found, but KeyManifest is not", __FUNCTION__), startupAcmIndex);
        }
        else if (!bgBootPolicyFound) {
            msg(usprintf("%s: startup ACM and Key Manifest found, Boot Policy is not", __FUNCTION__), kmIndex);
        }
        else {
            // Check key hashes
            if (!bgKmHash.isEmpty() && bgBpHash.isEmpty() && bgKmHash != bgBpHash) {
                msg(usprintf("%s: Boot Policy key hash stored in Key Manifest differs from the hash of public key stored in Boot Policy", __FUNCTION__), bpIndex);
                return U_SUCCESS;
            }
        }
    }
#endif

    return U_SUCCESS;
}

void FitParser::findFitRecursive(const UModelIndex & index, UModelIndex & found, UINT32 & fitOffset)
{
    // Sanity check
    if (!index.isValid()) {
        return;
    }
    
    // Process child items
    for (int i = 0; i < model->rowCount(index); i++) {
        findFitRecursive(index.model()->index(i, 0, index), found, fitOffset);
        
        if (found.isValid()) {
            // Found it, no need to process further
            return;
        }
    }
    
    // Check for all FIT signatures in item body
    UByteArray lastVtfBody = model->body(ffsParser->lastVtf);
    UINT32 storedFitAddress = *(const UINT32*)(lastVtfBody.constData() + lastVtfBody.size() - INTEL_FIT_POINTER_OFFSET);
    for (INT32 offset = (INT32)model->body(index).indexOf(INTEL_FIT_SIGNATURE);
         offset >= 0;
         offset = (INT32)model->body(index).indexOf(INTEL_FIT_SIGNATURE, offset + 1)) {
        // FIT candidate found, calculate its physical address
        UINT32 fitAddress = (UINT32)(model->base(index) + (UINT32)ffsParser->addressDiff + model->header(index).size() + (UINT32)offset);
        
        // Check FIT address to be stored in the last VTF
        if (fitAddress == storedFitAddress) {
            found = index;
            fitOffset = offset;
            msg(usprintf("%s: real FIT table found at physical address %08Xh", __FUNCTION__, fitAddress), found);
            break;
        }
        else if (model->rowCount(index) == 0) { // Show messages only to leaf items
            msg(usprintf("%s: FIT table candidate found, but not referenced from the last VTF", __FUNCTION__), index);
        }
    }
}

USTATUS FitParser::parseFitEntryMicrocode(const UByteArray & microcode, const UINT32 localOffset, const UModelIndex & parent, UString & info, UINT32 &realSize)
{
    U_UNUSED_PARAMETER(parent);
    if ((UINT32)microcode.size() - localOffset < sizeof(INTEL_MICROCODE_HEADER)) {
        return U_INVALID_MICROCODE;
    }
    
    const INTEL_MICROCODE_HEADER* ucodeHeader = (const INTEL_MICROCODE_HEADER*)(microcode.constData() + localOffset);
    if (!ffsParser->microcodeHeaderValid(ucodeHeader)) {
        return U_INVALID_MICROCODE;
    }
    
    if ((UINT32)microcode.size() - localOffset < ucodeHeader->TotalSize) {
        return U_INVALID_MICROCODE;
    }
    
    // Valid microcode found
    info = usprintf("CpuSignature: %08Xh, Revision: %08Xh, Date: %02X.%02X.%04X",
                    ucodeHeader->ProcessorSignature,
                    ucodeHeader->UpdateRevision,
                    ucodeHeader->DateDay,
                    ucodeHeader->DateMonth,
                    ucodeHeader->DateYear);
    realSize = ucodeHeader->TotalSize;
    
    return U_SUCCESS;
}

USTATUS FitParser::parseFitEntryAcm(const UByteArray & acm, const UINT32 localOffset, const UModelIndex & parent, UString & info, UINT32 &realSize)
{
    if ((UINT32)acm.size() < localOffset + sizeof(INTEL_ACM_HEADER)) {
        return U_INVALID_ACM;
    }
    
    const INTEL_ACM_HEADER* header = (const INTEL_ACM_HEADER*)(acm.constData() + localOffset);
    if (header->ModuleType != INTEL_ACM_MODULE_TYPE || header->ModuleVendor != INTEL_ACM_MODULE_VENDOR) {
        return U_INVALID_ACM;
    }
    
    UINT32 acmSize = header->ModuleSize * sizeof(UINT32);
    if ((UINT32)acm.size() < localOffset + acmSize) {
        return U_INVALID_ACM;
    }
    
    realSize = acmSize;
    
    // Valid ACM found
    info = usprintf("LocalOffset: %08Xh, EntryPoint: %08Xh, ACM SVN: %04Xh, Date: %02X.%02X.%04X",
                    localOffset,
                    header->EntryPoint,
                    header->AcmSvn,
                    header->DateDay,
                    header->DateMonth,
                    header->DateYear);
   
    // Populate ACM info
    UString acmInfo;
    if (header->ModuleSubtype == INTEL_ACM_MODULE_SUBTYPE_TXT_ACM) {
        acmInfo = "\n\nTXT ACM ";
    }
    else if(header->ModuleSubtype == INTEL_ACM_MODULE_SUBTYPE_S_ACM) {
        acmInfo = "\n\nS-ACM ";
    }
    else if (header->ModuleSubtype == INTEL_ACM_MODULE_SUBTYPE_BOOTGUARD) {
        acmInfo = "\n\nBootGuard ACM ";
    }
    else {
        acmInfo = "\n\nIntel ACM ";
    }
    
    acmInfo += usprintf("found at base %Xh\n"
                        "ModuleType: %04Xh        ModuleSubtype: %04Xh\n"
                        "HeaderLength: %08Xh  HeaderVersion: %08Xh\n"
                        "ChipsetId:  %04Xh        Flags: %04Xh\n"
                        "ModuleVendor: %04Xh      Date: %02X.%02X.%04X\n"
                        "ModuleSize: %08Xh    EntryPoint: %08Xh\n"
                        "AcmSvn: %04Xh            GdtBase: %08Xh\n"
                        "GdtMax: %08Xh        SegSel: %08Xh\n"
                        "KeySize: %08Xh\n",
                        model->base(parent) + localOffset,
                        header->ModuleType,
                        header->ModuleSubtype,
                        header->ModuleSize * (UINT32)sizeof(UINT32),
                        header->HeaderVersion,
                        header->ChipsetId,
                        header->Flags,
                        header->ModuleVendor,
                        header->DateDay, header->DateMonth, header->DateYear,
                        header->ModuleSize * (UINT32)sizeof(UINT32),
                        header->EntryPoint,
                        header->AcmSvn,
                        header->GdtBase,
                        header->GdtMax,
                        header->SegmentSel,
                        header->KeySize * (UINT32)sizeof(UINT32));
    // Add PubKey
    acmInfo += usprintf("\nACM RSA Public Key (Exponent: %Xh):", header->RsaPubExp);
    for (UINT16 i = 0; i < sizeof(header->RsaPubKey); i++) {
        if (i % 32 == 0) acmInfo += UString("\n");
        acmInfo += usprintf("%02X", header->RsaPubKey[i]);
    }
    acmInfo += "\n";
    
    // Add RsaSig
    acmInfo += UString("\nACM RSA Signature:");
    for (UINT16 i = 0; i < sizeof(header->RsaSig); i++) {
        if (i % 32 == 0) acmInfo += UString("\n");
        acmInfo += usprintf("%02X", header->RsaSig[i]);
    }
    acmInfo += "\n";

    // TODO: need to stop this "securityInfo" string building madness and use a message vector instead
    securityInfo += acmInfo;
    
    bgAcmFound = true;
    return U_SUCCESS;
}

USTATUS FitParser::parseFitEntryBootGuardKeyManifest(const UByteArray & keyManifest, const UINT32 localOffset, const UModelIndex & parent, UString & info, UINT32 &realSize)
{
    U_UNUSED_PARAMETER(realSize);
    
    if ((UINT32)keyManifest.size() < localOffset + sizeof(INTEL_BOOT_GUARD_KEY_MANIFEST)) {
        return U_INVALID_BOOT_GUARD_KEY_MANIFEST;
    }
    
    const INTEL_BOOT_GUARD_KEY_MANIFEST* header_v1 = (const INTEL_BOOT_GUARD_KEY_MANIFEST*)(keyManifest.constData() + localOffset);
    if (header_v1->Tag != INTEL_BOOT_GUARD_KEY_MANIFEST_TAG) {
        return U_INVALID_BOOT_GUARD_KEY_MANIFEST;
    }
    
    // Check for known Key Manifest version
    UString kmInfo;
    if (header_v1->Version >= INTEL_BOOT_GUARD_KEY_MANIFEST_VERSION_10
        && header_v1->Version <= INTEL_BOOT_GUARD_KEY_MANIFEST_VERSION_1F) {
        // Use v1 header
        
        // Valid KM found
        info = usprintf("LocalOffset: %08Xh, Version: %02Xh, KM Version: %02Xh, KM SVN: %02Xh, KM ID: %02Xh",
                        localOffset,
                        header_v1->Version,
                        header_v1->KmVersion,
                        header_v1->KmSvn,
                        header_v1->KmId);
        
        // Populate KM info
        kmInfo = usprintf("Intel BootGuard Key manifest found at base %Xh\n"
                          "Tag: __KEYM__  Version: %02Xh\n"
                          "KmVersion: %02Xh  KmSvn: %02Xh  KmId: %02Xh\n",
                          model->base(parent) + localOffset,
                          header_v1->Version,
                          header_v1->KmVersion,
                          header_v1->KmSvn,
                          header_v1->KmId);
        
        // Add hash of Key Manifest PubKey, this hash will be written to FPFs
        UINT8 hash[SHA256_HASH_SIZE];
        sha256(&header_v1->KeyManifestSignature.PubKey.Modulus, sizeof(header_v1->KeyManifestSignature.PubKey.Modulus), hash);
        kmInfo += UString("\n\nKey Manifest RSA Public Key Hash:\n");
        for (UINT8 i = 0; i < sizeof(hash); i++) {
            kmInfo += usprintf("%02X", hash[i]);
        }
        
        // Add BpKeyHash
        kmInfo += UString("\n\nBoot Policy RSA Public Key Hash:\n");
        for (UINT8 i = 0; i < sizeof(header_v1->BpKeyHash.HashBuffer); i++) {
            kmInfo += usprintf("%02X", header_v1->BpKeyHash.HashBuffer[i]);
        }
        bgKmHash = UByteArray((const char*)header_v1->BpKeyHash.HashBuffer, sizeof(header_v1->BpKeyHash.HashBuffer));
        
        // Add Key Manifest PubKey
        kmInfo += usprintf("\n\nKey Manifest RSA Public Key (Exponent: %Xh):", header_v1->KeyManifestSignature.PubKey.Exponent);
        for (UINT16 i = 0; i < sizeof(header_v1->KeyManifestSignature.PubKey.Modulus); i++) {
            if (i % 32 == 0) kmInfo += UString("\n");
            kmInfo += usprintf("%02X", header_v1->KeyManifestSignature.PubKey.Modulus[i]);
        }
        
        // Add Key Manifest Signature
        kmInfo += UString("\n\nKey Manifest RSA Signature:");
        for (UINT16 i = 0; i < sizeof(header_v1->KeyManifestSignature.Signature.Signature); i++) {
            if (i % 32 == 0) kmInfo += UString("\n");
            kmInfo += usprintf("%02X", header_v1->KeyManifestSignature.Signature.Signature[i]);
        }
    }
    else if (header_v1->Version >= INTEL_BOOT_GUARD_KEY_MANIFEST_VERSION_20
             && header_v1->Version <= INTEL_BOOT_GUARD_KEY_MANIFEST_VERSION_2F) {
        // Use v2 header
        if ((UINT32)keyManifest.size() < localOffset + sizeof(INTEL_BOOT_GUARD_KEY_MANIFEST2)) {
            return U_INVALID_BOOT_GUARD_KEY_MANIFEST;
        }
        
        const INTEL_BOOT_GUARD_KEY_MANIFEST2* header_v2 = (const INTEL_BOOT_GUARD_KEY_MANIFEST2*)(keyManifest.constData() + localOffset);
        if (header_v2->Tag != INTEL_BOOT_GUARD_KEY_MANIFEST_TAG) {
            return U_INVALID_BOOT_GUARD_KEY_MANIFEST;
        }
        
        // Valid KM found
        info = usprintf("LocalOffset: %08Xh, Version: %02Xh, KM Version: %02Xh, KM SVN: %02Xh, KM ID: %02Xh",
                        localOffset,
                        header_v2->Version,
                        header_v2->KmVersion,
                        header_v2->KmSvn,
                        header_v2->KmId);
        
        // Populate KM info
        kmInfo = usprintf("Intel BootGuard Key manifest found at base %Xh\n"
                          "Tag: __KEYM__  Version: %02Xh\n"
                          "KmVersion: %02Xh  KmSvn: %02Xh  KmId: %02Xh\n"
                          "SignatureOffset: %04Xh  HashAlgorithmId: %04Xh\n"
                          "TotalKeys: %04Xh\n",
                          model->base(parent) + localOffset,
                          header_v2->Version,
                          header_v2->KmVersion,
                          header_v2->KmSvn,
                          header_v2->KmId,
                          header_v2->SignatureOffset,
                          header_v2->HashAlgorithmId,
                          header_v2->TotalKeys);

//TODO: reenable
#if 0 // Disable for now, incorrect for non-SHA256 hashes
        // Add hash of Key Manifest PubKey, this hash will be written to FPFs
        UINT8 hash[SHA256_HASH_SIZE];
        sha256(&header_v2->KeyManifestSignature.PubKey.Modulus, sizeof(header_v2->KeyManifestSignature.PubKey.Modulus), hash);
        kmInfo += UString("\n\nKey Manifest RSA Public Key Hash:\n");
        for (UINT8 i = 0; i < sizeof(hash); i++) {
            kmInfo += usprintf("%02X", hash[i]);
        }
        
        // Add BpKeyHash
        kmInfo += UString("\n\nBoot Policy RSA Public Key Hash:\n");
        for (UINT8 i = 0; i < sizeof(header_v2->BpKeyHash.HashBuffer); i++) {
            kmInfo += usprintf("%02X", header_v2->BpKeyHash.HashBuffer[i]);
        }
        bgKmHash = UByteArray((const char*)header_v2->BpKeyHash.HashBuffer, sizeof(header_v2->BpKeyHash.HashBuffer));
        
        // Add Key Manifest PubKey
        kmInfo += usprintf("\n\nKey Manifest RSA Public Key (Exponent: %Xh):", header_v2->KeyManifestSignature.PubKey.Exponent);
        for (UINT16 i = 0; i < sizeof(header_v2->KeyManifestSignature.PubKey.Modulus); i++) {
            if (i % 32 == 0) kmInfo += UString("\n");
            kmInfo += usprintf("%02X", header_v2->KeyManifestSignature.PubKey.Modulus[i]);
        }
        
        // Add Key Manifest Signature
        kmInfo += UString("\n\nKey Manifest RSA Signature:");
        for (UINT16 i = 0; i < sizeof(header_v2->KeyManifestSignature.Signature.Signature); i++) {
            if (i % 32 == 0) kmInfo += UString("\n");
            kmInfo += usprintf("%02X", header_v2->KeyManifestSignature.Signature.Signature[i]);
        }
#endif
    }
    else {
        // Unknown version, no way to meaningfully parse it.
        msg(usprintf("%s: unknown Intel BootGuard Key Manifest version %02Xh", __FUNCTION__, header_v1->Version), parent);
    }
    
    // TODO: need to stop this "securityInfo" string building madness and use a message vector instead
    securityInfo += kmInfo;
    
    bgKeyManifestFound = true;
    return U_SUCCESS;
}

USTATUS FitParser::findNextBootGuardBootPolicyElement(const UByteArray & bootPolicy, const UINT32 elementOffset, UINT32 & nextElementOffset, UINT32 & nextElementSize)
{
    UINT32 dataSize = (UINT32)bootPolicy.size();
    if (dataSize < sizeof(UINT64)) {
        return U_ELEMENTS_NOT_FOUND;
    }
    
    UINT32 offset = elementOffset;
    for (; offset < dataSize - sizeof(UINT64); offset++) {
        const UINT64* currentPos = (const UINT64*)(bootPolicy.constData() + offset);
        if (*currentPos == INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_IBB_ELEMENT_TAG
            && offset + sizeof(INTEL_BOOT_GUARD_IBB_ELEMENT) < dataSize) {
            const INTEL_BOOT_GUARD_IBB_ELEMENT* header = (const INTEL_BOOT_GUARD_IBB_ELEMENT*)currentPos;
            // Check that all segments are present
            if (offset + sizeof(INTEL_BOOT_GUARD_IBB_ELEMENT) + sizeof(INTEL_BOOT_GUARD_IBB_SEGMENT_ELEMENT) * header->IbbSegCount < dataSize) {
                nextElementOffset = offset;
                nextElementSize = sizeof(INTEL_BOOT_GUARD_IBB_ELEMENT) + sizeof(INTEL_BOOT_GUARD_IBB_SEGMENT_ELEMENT) * header->IbbSegCount;
                return U_SUCCESS;
            }
        }
        else if (*currentPos == INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_PLATFORM_MANUFACTURER_ELEMENT_TAG && offset + sizeof(INTEL_BOOT_GUARD_PLATFORM_MANUFACTURER_ELEMENT) < dataSize) {
            const INTEL_BOOT_GUARD_PLATFORM_MANUFACTURER_ELEMENT* header = (const INTEL_BOOT_GUARD_PLATFORM_MANUFACTURER_ELEMENT*)currentPos;
            // Check that data is present
            if (offset + sizeof(INTEL_BOOT_GUARD_PLATFORM_MANUFACTURER_ELEMENT) + header->DataSize < dataSize) {
                nextElementOffset = offset;
                nextElementSize = sizeof(INTEL_BOOT_GUARD_PLATFORM_MANUFACTURER_ELEMENT) + header->DataSize;
                return U_SUCCESS;
            }
        }
        else if (*currentPos == INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT_TAG && offset + sizeof(INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT) < dataSize) {
            nextElementOffset = offset;
            nextElementSize = sizeof(INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT);
            return U_SUCCESS;
        }
    }
    
    return U_ELEMENTS_NOT_FOUND;
}

USTATUS FitParser::parseFitEntryBootGuardBootPolicy(const UByteArray & bootPolicy, const UINT32 localOffset, const UModelIndex & parent, UString & info, UINT32 &realSize)
{
    U_UNUSED_PARAMETER(realSize);
    if ((UINT32)bootPolicy.size() < localOffset + sizeof(INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER)) {
        return U_INVALID_BOOT_GUARD_BOOT_POLICY;
    }
    
    const INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER* header_v1 = (const INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER*)(bootPolicy.constData() + localOffset);
    if (header_v1->Tag != BG_BOOT_POLICY_MANIFEST_HEADER_TAG) {
        return U_INVALID_BOOT_GUARD_BOOT_POLICY;
    }
    
    // Check for known Boot Policy version
    UString bpInfo;
    if (header_v1->Version >= INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_VERSION_10
        && header_v1->Version <= INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_VERSION_1F) {
        // Contunue using header v1
        
        // Valid BPM found
        info = usprintf("LocalOffset: %08Xh, BP SVN: %02Xh, ACM SVN: %02Xh",
                        localOffset,
                        header_v1->BPSVN,
                        header_v1->ACMSVN);
        
        // Add BP header info
        bpInfo = usprintf("\n\nIntel BootGuard Boot Policy Manifest found at base %Xh\n"
                          "Tag: __ACBP__ Version: %02Xh HeaderVersion: %02Xh\n"
                          "PMBPMVersion: %02Xh PBSVN: %02Xh ACMSVN: %02Xh NEMDataSize: %04Xh\n",
                          model->base(parent) + localOffset,
                          header_v1->Version,
                          header_v1->HeaderVersion,
                          header_v1->PMBPMVersion,
                          header_v1->BPSVN,
                          header_v1->ACMSVN,
                          header_v1->NEMDataSize);
        
        // Iterate over elements to get them all
        UINT32 elementOffset = 0;
        UINT32 elementSize = 0;
        USTATUS status = findNextBootGuardBootPolicyElement(bootPolicy, localOffset + sizeof(INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER), elementOffset, elementSize);
        while (status == U_SUCCESS) {
            const UINT64* currentPos = (const UINT64*)(bootPolicy.constData() + elementOffset);
            if (*currentPos == INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_IBB_ELEMENT_TAG) {
                const INTEL_BOOT_GUARD_IBB_ELEMENT* elementHeader = (const INTEL_BOOT_GUARD_IBB_ELEMENT*)currentPos;
                // Valid IBB element found
                bpInfo += usprintf("\n\nInitial Boot Block Element found at base %Xh\n"
                                   "Tag: __IBBS__       Version: %02Xh\n"
                                   "Flags: %08Xh    IbbMchBar: %08Xh VtdBar: %08Xh\n"
                                   "PmrlBase: %08Xh PmrlLimit: %08Xh EntryPoint: %08Xh",
                                   model->base(parent) + localOffset + elementOffset,
                                   elementHeader->Version,
                                   elementHeader->Flags,
                                   (UINT32)elementHeader->IbbMchBar,
                                   (UINT32)elementHeader->VtdBar,
                                   elementHeader->PmrlBase,
                                   elementHeader->PmrlLimit,
                                   elementHeader->EntryPoint);
                
                // Add PostIbbHash
                bpInfo += UString("\n\nPost IBB Hash:\n");
                for (UINT8 i = 0; i < sizeof(elementHeader->IbbHash.HashBuffer); i++) {
                    bpInfo += usprintf("%02X", elementHeader->IbbHash.HashBuffer[i]);
                }
                
                // Check for non-empry PostIbbHash
                UByteArray postIbbHash((const char*)elementHeader->IbbHash.HashBuffer, sizeof(elementHeader->IbbHash.HashBuffer));
                if (postIbbHash.count('\x00') != postIbbHash.size()
                    && postIbbHash.count('\xFF') != postIbbHash.size()) {
                    PROTECTED_RANGE range = {};
                    range.Type = PROTECTED_RANGE_INTEL_BOOT_GUARD_POST_IBB;
                    range.Hash = postIbbHash;
                    ffsParser->protectedRanges.push_back(range);
                }
                
                // Add Digest
                bgBpDigest = UByteArray((const char*)elementHeader->Digest.HashBuffer, sizeof(elementHeader->Digest.HashBuffer));
                bpInfo += UString("\n\nIBB Digest:\n");
                for (UINT8 i = 0; i < (UINT8)bgBpDigest.size(); i++) {
                    bpInfo += usprintf("%02X", (UINT8)bgBpDigest.at(i));
                }
                
                // Add all IBB segments
                bpInfo += UString("\n\nIBB Segments:\n");
                const INTEL_BOOT_GUARD_IBB_SEGMENT_ELEMENT* segments = (const INTEL_BOOT_GUARD_IBB_SEGMENT_ELEMENT*)(elementHeader + 1);
                for (UINT8 i = 0; i < elementHeader->IbbSegCount; i++) {
                    bpInfo += usprintf("Flags: %04Xh Address: %08Xh Size: %08Xh\n",
                                       segments[i].Flags, segments[i].Base, segments[i].Size);
                    if (segments[i].Flags == INTEL_BOOT_GUARD_IBB_SEGMENT_FLAG_IBB) {
                        PROTECTED_RANGE range = {};
                        range.Offset = segments[i].Base;
                        range.Size = segments[i].Size;
                        range.Type = PROTECTED_RANGE_INTEL_BOOT_GUARD_IBB;
                        ffsParser->protectedRanges.push_back(range);
                    }
                }
            }
            else if (*currentPos == INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_PLATFORM_MANUFACTURER_ELEMENT_TAG) {
                const INTEL_BOOT_GUARD_PLATFORM_MANUFACTURER_ELEMENT* elementHeader = (const INTEL_BOOT_GUARD_PLATFORM_MANUFACTURER_ELEMENT*)currentPos;
                bpInfo += usprintf("\n\nPlatform Manufacturer Data Element found at base %Xh\n"
                                   "Tag: __PMDA__ Version: %02Xh DataSize: %02Xh",
                                   model->base(parent) + localOffset + elementOffset,
                                   elementHeader->Version,
                                   elementHeader->DataSize);
                // Check for Microsoft PMDA hash data
                const INTEL_BOOT_GUARD_MICROSOFT_PMDA_HEADER* pmdaHeader = (const INTEL_BOOT_GUARD_MICROSOFT_PMDA_HEADER*)(elementHeader + 1);
                if (pmdaHeader->Version == INTEL_BOOT_GUARD_MICROSOFT_PMDA_VERSION
                    && elementHeader->DataSize == sizeof(INTEL_BOOT_GUARD_MICROSOFT_PMDA_HEADER) + sizeof(INTEL_BOOT_GUARD_MICROSOFT_PMDA_ENTRY)*pmdaHeader->NumEntries) {
                    // Add entries
                    bpInfo += UString("\n\nMicrosoft PMDA-based protected ranges:\n");
                    const INTEL_BOOT_GUARD_MICROSOFT_PMDA_ENTRY* entries = (const INTEL_BOOT_GUARD_MICROSOFT_PMDA_ENTRY*)(pmdaHeader + 1);
                    for (UINT32 i = 0; i < pmdaHeader->NumEntries; i++) {
                        bpInfo += usprintf("Address: %08Xh Size: %08Xh\n", entries[i].Address, entries[i].Size);
                        bpInfo += UString("Hash: ");
                        for (UINT8 j = 0; j < sizeof(entries[i].Hash); j++) {
                            bpInfo += usprintf("%02X", entries[i].Hash[j]);
                        }
                        bpInfo += UString("\n");
                        
                        PROTECTED_RANGE range = {};
                        range.Offset = entries[i].Address;
                        range.Size = entries[i].Size;
                        range.Hash = UByteArray((const char*)entries[i].Hash, sizeof(entries[i].Hash));
                        range.Type = PROTECTED_RANGE_VENDOR_HASH_MICROSOFT;
                        ffsParser->protectedRanges.push_back(range);
                    }
                }
                else {
                    // Add raw data
                    const UINT8* data = (const UINT8*)(elementHeader + 1);
                    for (UINT16 i = 0; i < elementHeader->DataSize; i++) {
                        if (i % 32 == 0) bpInfo += UString("\n");
                        bpInfo += usprintf("%02X", data[i]);
                    }
                    bpInfo += UString("\n");
                }
            }
            else if (*currentPos == INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT_TAG) {
                const INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT* elementHeader = (const INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT*)currentPos;
                bpInfo += usprintf("\n\nBoot Policy Signature Element found at base %Xh\n"
                                   "Tag: __PMSG__ Version: %02Xh",
                                   model->base(parent) + localOffset + elementOffset,
                                   elementHeader->Version);
                
                // Add PubKey
                bpInfo += usprintf("\n\nBoot Policy RSA Public Key (Exponent: %Xh):", elementHeader->KeySignature.PubKey.Exponent);
                for (UINT16 i = 0; i < sizeof(elementHeader->KeySignature.PubKey.Modulus); i++) {
                    if (i % 32 == 0) bpInfo += UString("\n");
                    bpInfo += usprintf("%02X", elementHeader->KeySignature.PubKey.Modulus[i]);
                }
                
                // Calculate and add PubKey hash
                UINT8 hash[SHA256_HASH_SIZE];
                sha256(&elementHeader->KeySignature.PubKey.Modulus, sizeof(elementHeader->KeySignature.PubKey.Modulus), hash);
                bpInfo += UString("\n\nBoot Policy RSA Public Key Hash:");
                for (UINT8 i = 0; i < sizeof(hash); i++) {
                    if (i % 32 == 0) bpInfo += UString("\n");
                    bpInfo += usprintf("%02X", hash[i]);
                }
                bgBpHash = UByteArray((const char*)hash, sizeof(hash));
                
                // Add Signature
                bpInfo += UString("\n\nBoot Policy RSA Signature:");
                for (UINT16 i = 0; i < sizeof(elementHeader->KeySignature.Signature.Signature); i++) {
                    if (i % 32 == 0) bpInfo += UString("\n");
                    bpInfo += usprintf("%02X", elementHeader->KeySignature.Signature.Signature[i]);
                }
            }
            status = findNextBootGuardBootPolicyElement(bootPolicy, elementOffset + elementSize, elementOffset, elementSize);
        }
    }
    else if (header_v1->Version >= INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_VERSION_20
             && header_v1->Version <= INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_VERSION_2F) {
        if ((UINT32)bootPolicy.size() < localOffset + sizeof(INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER2)) {
            return U_INVALID_BOOT_GUARD_BOOT_POLICY;
        }
        
        const INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER2* header_v2 = (const INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER2*)(bootPolicy.constData() + localOffset);
        if (header_v1->Tag != BG_BOOT_POLICY_MANIFEST_HEADER_TAG) {
            return U_INVALID_BOOT_GUARD_BOOT_POLICY;
        }
        
        // Valid BPM found
        info = usprintf("LocalOffset: %08Xh, BP SVN: %02Xh, ACM SVN: %02Xh",
                        localOffset,
                        header_v2->BPSVN,
                        header_v2->ACMSVN);
        
        // Add BP header info
        bpInfo = usprintf("\n\nIntel BootGuard Boot Policy Manifest found at base %Xh\n"
                          "Tag: __ACBP__ Version: %02Xh HeaderVersion: %02Xh\n"
                          "PMBPMVersion: %02Xh PBSVN: %02Xh ACMSVN: %02Xh NEMDataSize: %04Xh\n"
                          "HeaderSize: %04Xh RSAEntryOffset: %04Xh\n",
                          model->base(parent) + localOffset,
                          header_v2->Version,
                          header_v2->HeaderVersion,
                          header_v2->PMBPMVersion,
                          header_v2->BPSVN,
                          header_v2->ACMSVN,
                          header_v2->NEMDataSize,
                          header_v2->HeaderSize,
                          header_v2->RSAEntryOffset);
        
        // Iterate over elements to get them all
        UINT32 elementOffset = 0;
        UINT32 elementSize = 0;
        USTATUS status = findNextBootGuardBootPolicyElement(bootPolicy, localOffset + sizeof(INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER2), elementOffset, elementSize);
        while (status == U_SUCCESS) {
            const UINT64* currentPos = (const UINT64*)(bootPolicy.constData() + elementOffset);
            if (*currentPos == INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_IBB_ELEMENT_TAG) {
                const INTEL_BOOT_GUARD_IBB_ELEMENT2* elementHeader = (const INTEL_BOOT_GUARD_IBB_ELEMENT2*)currentPos;
                // Valid IBB element found
                bpInfo += usprintf("\n\nInitial Boot Block Element found at base %Xh\n"
                                   "Tag: __IBBS__     Version: %02Xh\n"
                                   "Flags: %08Xh      IbbMchBar: %08Xh  VtdBar: %08Xh\n"
                                   "PmrlBase: %08Xh   PmrlLimit: %08Xh  EntryPoint: %08Xh\n"
                                   "PolicyTimerVal: %02Xh   PostIbbHash: %08Xh\n"
                                   "SizeOfDigests: %04Xh  NumOfDigests: %04Xh",
                                   model->base(parent) + localOffset + elementOffset,
                                   elementHeader->Version,
                                   elementHeader->Flags,
                                   (UINT32)elementHeader->IbbMchBar,
                                   (UINT32)elementHeader->VtdBar,
                                   elementHeader->PmrlBase,
                                   elementHeader->PmrlLimit,
                                   elementHeader->EntryPoint,
                                   elementHeader->PolicyTimerVal,
                                   elementHeader->PostIbbHash,
                                   elementHeader->SizeOfDigests,
                                   elementHeader->NumOfDigests);
                // Add Digest
                bpInfo += UString("\n\nIBB Digests:\n");
                char* digest = (char*)(elementHeader + 1);
                for (UINT16 i = 0; i < elementHeader->NumOfDigests; i++) {
                    if (((INTEL_BOOT_GUARD_HASH_HEADER*)digest)->HashAlgorithmId == INTEL_BOOT_GUARD_HASH_ALGORITHM_SHA256)
                        bpInfo += usprintf("\n%02X - SHA256 Hash:\n", i + 1);
                    else if (((INTEL_BOOT_GUARD_HASH_HEADER*)digest)->HashAlgorithmId == INTEL_BOOT_GUARD_HASH_ALGORITHM_SHA384)
                        bpInfo += usprintf("\n%02X - SHA384 Hash:\n", i + 1);
                    else if (((INTEL_BOOT_GUARD_HASH_HEADER*)digest)->HashAlgorithmId == INTEL_BOOT_GUARD_HASH_ALGORITHM_SHA1)
                        bpInfo += usprintf("\n%02X - SHA1 Hash:\n", i + 1);
                    else
                        bpInfo += usprintf("\n%02X - Unknown Hash:\n", i + 1);
                    
                    UINT16 digestSize = ((INTEL_BOOT_GUARD_HASH_HEADER*)digest)->Size;
                    bgBpDigest = UByteArray((const char*)(digest + sizeof(INTEL_BOOT_GUARD_HASH_HEADER)), digestSize);
                    for (UINT16 i = 0; i < digestSize; i++)
                        bpInfo += usprintf("%02X", (UINT8)bgBpDigest.at(i));
                    
                    digest += sizeof(INTEL_BOOT_GUARD_HASH_HEADER) + digestSize;
                }
                
                // Add all IBB segments
                // TODO: shady arithmetics is shady, needs fixing
#if 0 // Disabled for now
                bpInfo += UString("\n\nIBB Segments:\n");
                const INTEL_BOOT_GUARD_IBB_SEGMENT_ELEMENT* segments = (const INTEL_BOOT_GUARD_IBB_SEGMENT_ELEMENT*)((char*)elementHeader + sizeof(INTEL_BOOT_GUARD_IBB_ELEMENT2) + elementHeader->SizeOfDigests + 3); // WTF is +3?
                UINT8 IbbSegCount = *((char*)segments - 1); // WTF is -1?
                for (UINT8 i = 0; i < IbbSegCount; i++) {
                    bpInfo += usprintf("Flags: %04Xh Address: %08Xh Size: %08Xh\n",
                                             segments[i].Flags, segments[i].Base, segments[i].Size);
                    if (segments[i].Flags == INTEL_BOOT_GUARD_IBB_SEGMENT_FLAG_IBB) {
                        PROTECTED_RANGE range = {};
                        range.Offset = segments[i].Base;
                        range.Size = segments[i].Size;
                        range.Type = PROTECTED_RANGE_INTEL_BOOT_GUARD_IBB;
                        ffsParser->protectedRanges.push_back(range);
                    }
                }
#endif
            }
            else if (*currentPos == INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_PLATFORM_MANUFACTURER_ELEMENT_TAG) {
                const INTEL_BOOT_GUARD_PLATFORM_MANUFACTURER_ELEMENT* elementHeader = (const INTEL_BOOT_GUARD_PLATFORM_MANUFACTURER_ELEMENT*)currentPos;
                bpInfo += usprintf("\n\nPlatform Manufacturer Data Element found at base %Xh\n"
                                   "Tag: __PMDA__ Version: %02Xh DataSize: %02Xh",
                                   model->base(parent) + localOffset + elementOffset,
                                   elementHeader->Version,
                                   elementHeader->DataSize);
                // Check for Microsoft PMDA hash data
                const INTEL_BOOT_GUARD_MICROSOFT_PMDA_HEADER* pmdaHeader = (const INTEL_BOOT_GUARD_MICROSOFT_PMDA_HEADER*)(elementHeader + 1);
                if (pmdaHeader->Version == INTEL_BOOT_GUARD_MICROSOFT_PMDA_VERSION
                    && elementHeader->DataSize == sizeof(INTEL_BOOT_GUARD_MICROSOFT_PMDA_HEADER) + sizeof(INTEL_BOOT_GUARD_MICROSOFT_PMDA_ENTRY)*pmdaHeader->NumEntries) {
                    // Add entries
                    bpInfo += UString("\n\nMicrosoft PMDA-based protected ranges:\n");
                    const INTEL_BOOT_GUARD_MICROSOFT_PMDA_ENTRY* entries = (const INTEL_BOOT_GUARD_MICROSOFT_PMDA_ENTRY*)(pmdaHeader + 1);
                    for (UINT32 i = 0; i < pmdaHeader->NumEntries; i++) {
                        bpInfo += usprintf("Address: %08Xh Size: %08Xh\n", entries[i].Address, entries[i].Size);
                        bpInfo += UString("Hash: ");
                        for (UINT8 j = 0; j < sizeof(entries[i].Hash); j++) {
                            bpInfo += usprintf("%02X", entries[i].Hash[j]);
                        }
                        bpInfo += UString("\n");
                        
                        PROTECTED_RANGE range = {};
                        range.Offset = entries[i].Address;
                        range.Size = entries[i].Size;
                        range.Hash = UByteArray((const char*)entries[i].Hash, sizeof(entries[i].Hash));
                        range.Type = PROTECTED_RANGE_VENDOR_HASH_MICROSOFT;
                        ffsParser->protectedRanges.push_back(range);
                    }
                }
                else {
                    // Add raw data
                    const UINT8* data = (const UINT8*)(elementHeader + 1);
                    for (UINT16 i = 0; i < elementHeader->DataSize; i++) {
                        if (i % 32 == 0) bpInfo += UString("\n");
                        bpInfo += usprintf("%02X", data[i]);
                    }
                    bpInfo += UString("\n");
                }
            }
            else if (*currentPos == INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT_TAG) {
                const INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT2* elementHeader = (const INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT2*)currentPos;
                bpInfo += usprintf("\n\nBoot Policy Signature Element found at base %Xh\n"
                                   "Tag: __PMSG__ Version: %02Xh",
                                   model->base(parent) + localOffset + elementOffset,
                                   elementHeader->Version);
                
                // Add PubKey
                bpInfo += usprintf("\n\nBoot Policy RSA Public Key (Exponent: %Xh):", elementHeader->KeySignature.PubKey.Exponent);
                for (UINT16 i = 0; i < sizeof(elementHeader->KeySignature.PubKey.Modulus); i++) {
                    if (i % 32 == 0) bpInfo += UString("\n");
                    bpInfo += usprintf("%02X", elementHeader->KeySignature.PubKey.Modulus[i]);
                }
                
                // Calculate and add PubKey hash
                UINT8 hash[SHA256_HASH_SIZE];
                sha256(&elementHeader->KeySignature.PubKey.Modulus, sizeof(elementHeader->KeySignature.PubKey.Modulus), hash);
                bpInfo += UString("\n\nBoot Policy RSA Public Key Hash:");
                for (UINT8 i = 0; i < sizeof(hash); i++) {
                    if (i % 32 == 0) bpInfo += UString("\n");
                    bpInfo += usprintf("%02X", hash[i]);
                }
                bgBpHash = UByteArray((const char*)hash, sizeof(hash));
                
                // Add Signature
                bpInfo += UString("\n\nBoot Policy RSA Signature:");
                for (UINT16 i = 0; i < sizeof(elementHeader->KeySignature.Signature.Signature); i++) {
                    if (i % 32 == 0) bpInfo += UString("\n");
                    bpInfo += usprintf("%02X", elementHeader->KeySignature.Signature.Signature[i]);
                }
            }
            status = findNextBootGuardBootPolicyElement(bootPolicy, elementOffset + elementSize, elementOffset, elementSize);
        }
    }
    else {
        msg(usprintf("%s: unknown Intel BootGuard Boot Policy Manifest version %02Xh", __FUNCTION__, header_v1->Version), parent);
    }
    
    // TODO: need to stop this "securityInfo" string building madness and use a message vector instead
    securityInfo += bpInfo;
    
    bgBootPolicyFound = true;
    return U_SUCCESS;
}
