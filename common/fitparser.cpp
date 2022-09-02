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
    if (!index.isValid())
        return EFI_INVALID_PARAMETER;
    
    // Search for FIT
    UModelIndex fitIndex;
    UINT32 fitOffset;
    findFitRecursive(index, fitIndex, fitOffset);
    
    // FIT not found
    if (!fitIndex.isValid())
        return U_SUCCESS;
    
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
    UModelIndex acmIndex;
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
                        acmIndex = itemIndex;
                        break;
                        
                    case INTEL_FIT_TYPE_BOOT_GUARD_KEY_MANIFEST:
                        if ((UINT32)item.size() < localOffset + 0x8) {
                            return U_INVALID_BG_KEY_MANIFEST;
                        }

                        //TODO: parse BGKM
                        
                        bgKeyManifestFound = true;
                        kmIndex = itemIndex;
                        break;
                        
                    case INTEL_FIT_TYPE_BOOT_GUARD_BOOT_POLICY:
                        if ((UINT32)item.size() < localOffset + 0x8) {
                            return U_INVALID_BG_KEY_MANIFEST;
                        }

                        //TODO: parse BGBP
                        
                        break;
                        
                    default:
                        // Do nothing
                        status = U_SUCCESS;
                        break;
                }
                
                if (status != U_SUCCESS)
                    itemIndex = UModelIndex();
            }
            else {
                msg(usprintf("%s: FIT entry #%d not found in the image", __FUNCTION__, i), fitIndex);
            }
        }
        
        if (itemIndex.isValid()) {
            // Explicitly set the item referenced by FIT as fixed
            // TODO: lift this restriction after FIT builder is ready
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
    
    // Perform validation of BootGuard stuff
    if (bgAcmFound) {
        if (!bgKeyManifestFound) {
            msg(usprintf("%s: ACM found, but KeyManifest is not", __FUNCTION__), acmIndex);
        }
        else if (!bgBootPolicyFound) {
            msg(usprintf("%s: ACM and KeyManifest found, BootPolicy is not", __FUNCTION__), kmIndex);
        }
        else {
            // Check key hashes
            if (!bgKmHash.isEmpty() && bgBpHash.isEmpty() && bgKmHash != bgBpHash) {
                msg(usprintf("%s: BootPolicy key hash stored in KeyManifest differs from the hash of public key stored in BootPolicy", __FUNCTION__), bpIndex);
                return U_SUCCESS;
            }
        }
    }
    
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
        
        if (found.isValid())
            return;
    }
    
    // Check for all FIT signatures in item's body
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
    
    // Valid ACM found
    info = usprintf("LocalOffset: %08Xh, EntryPoint: %08Xh, ACM SVN: %04Xh, Date: %02X.%02X.%04X",
                    localOffset,
                    header->EntryPoint,
                    header->AcmSvn,
                    header->DateDay,
                    header->DateMonth,
                    header->DateYear
                    );
    realSize = acmSize;
    
    // Add ACM header info
    UString acmInfo;
    acmInfo += usprintf(" found at base %Xh\n"
                        "ModuleType: %04Xh         ModuleSubtype: %04Xh     HeaderLength: %08Xh\n"
                        "HeaderVersion: %08Xh  ChipsetId:  %04Xh        Flags: %04Xh\n"
                        "ModuleVendor: %04Xh       Date: %02X.%02X.%04X         ModuleSize: %08Xh\n"
                        "EntryPoint: %08Xh     AcmSvn: %04Xh\n"
                        "GdtBase: %08Xh       GdtMax: %08Xh\n"
                        "SegSel: %08Xh         KeySize: %08Xh\n",
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
                        header->KeySize * (UINT32)sizeof(UINT32)
                        );
    // Add PubKey
    acmInfo += usprintf("\n\nACM RSA Public Key (Exponent: %Xh):", header->RsaPubExp);
    for (UINT16 i = 0; i < sizeof(header->RsaPubKey); i++) {
        if (i % 32 == 0)
            acmInfo += UString("\n");
        acmInfo += usprintf("%02X", header->RsaPubKey[i]);
    }
    // Add RsaSig
    acmInfo += UString("\n\nACM RSA Signature:");
    for (UINT16 i = 0; i < sizeof(header->RsaSig); i++) {
        if (i % 32 == 0)
            acmInfo += UString("\n");
        acmInfo += usprintf("%02X", header->RsaSig[i]);
    }
    acmInfo += UString("\n------------------------------------------------------------------------\n\n");
    
    if(header->ModuleSubtype == INTEL_ACM_MODULE_SUBTYPE_TXT_ACM)
        securityInfo += "TXT ACM" + acmInfo;
    else if(header->ModuleSubtype == INTEL_ACM_MODULE_SUBTYPE_S_ACM)
        securityInfo += "S-ACM" + acmInfo;
    else if (header->ModuleSubtype == INTEL_ACM_MODULE_SUBTYPE_BOOTGUARD)
        securityInfo += "BootGuard ACM" + acmInfo;
    else
        securityInfo += "Intel ACM" + acmInfo;
    
    bgAcmFound = true;
    return U_SUCCESS;
}

USTATUS FitParser::parseFitEntryBootGuardKeyManifest(const UByteArray & keyManifest, const UINT32 localOffset, const UModelIndex & parent, UString & info, UINT32 &realSize)
{
    U_UNUSED_PARAMETER(realSize);
    if ((UINT32)keyManifest.size() < localOffset + sizeof(INTEL_BOOT_GUARD_KEY_MANIFEST)) {
        return U_INVALID_BG_KEY_MANIFEST;
    }
    
    const INTEL_BOOT_GUARD_KEY_MANIFEST* header = (const INTEL_BOOT_GUARD_KEY_MANIFEST*)(keyManifest.constData() + localOffset);
    if (header->Tag != INTEL_BOOT_GUARD_KEY_MANIFEST_TAG) {
        return U_INVALID_BG_KEY_MANIFEST;
    }
    
    // Valid KM found
    info = usprintf("LocalOffset: %08Xh, KM Version: %02Xh, KM SVN: %02Xh, KM ID: %02Xh",
                    localOffset,
                    header->KmVersion,
                    header->KmSvn,
                    header->KmId
                    );
    
    // Add KM header info
    securityInfo += usprintf("Intel BootGuard Key manifest found at base %Xh\n"
                             "Tag: __KEYM__ Version: %02Xh KmVersion: %02Xh KmSvn: %02Xh KmId: %02Xh",
                             model->base(parent) + localOffset,
                             header->Version,
                             header->KmVersion,
                             header->KmSvn,
                             header->KmId
                             );
    
    // Add hash of Key Manifest PubKey, this hash will be written to FPFs
    UINT8 hash[SHA256_HASH_SIZE];
    sha256(&header->KeyManifestSignature.PubKey.Modulus, sizeof(header->KeyManifestSignature.PubKey.Modulus), hash);
    securityInfo += UString("\n\nKey Manifest RSA Public Key Hash:\n");
    for (UINT8 i = 0; i < sizeof(hash); i++) {
        securityInfo += usprintf("%02X", hash[i]);
    }
    
    // Add BpKeyHash
    securityInfo += UString("\n\nBoot Policy RSA Public Key Hash:\n");
    for (UINT8 i = 0; i < sizeof(header->BpKeyHash.HashBuffer); i++) {
        securityInfo += usprintf("%02X", header->BpKeyHash.HashBuffer[i]);
    }
    bgKmHash = UByteArray((const char*)header->BpKeyHash.HashBuffer, sizeof(header->BpKeyHash.HashBuffer));
    
    // Add Key Manifest PubKey
    securityInfo += usprintf("\n\nKey Manifest RSA Public Key (Exponent: %Xh):",
                             header->KeyManifestSignature.PubKey.Exponent);
    for (UINT16 i = 0; i < sizeof(header->KeyManifestSignature.PubKey.Modulus); i++) {
        if (i % 32 == 0)
            securityInfo += UString("\n");
        securityInfo += usprintf("%02X", header->KeyManifestSignature.PubKey.Modulus[i]);
    }
    // Add Key Manifest Signature
    securityInfo += UString("\n\nKey Manifest RSA Signature:");
    for (UINT16 i = 0; i < sizeof(header->KeyManifestSignature.Signature.Signature); i++) {
        if (i % 32 == 0)
            securityInfo += UString("\n");
        securityInfo += usprintf("%02X", header->KeyManifestSignature.Signature.Signature[i]);
    }
    securityInfo += UString("\n------------------------------------------------------------------------\n\n");
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
        if (*currentPos == INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_IBB_ELEMENT_TAG && offset + sizeof(INTEL_BOOT_GUARD_IBB_ELEMENT) < dataSize) {
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
        return U_INVALID_BG_BOOT_POLICY;
    }
    
    const INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER* header = (const INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER*)(bootPolicy.constData() + localOffset);
    if (header->Tag != BG_BOOT_POLICY_MANIFEST_HEADER_TAG) {
        return U_INVALID_BG_BOOT_POLICY;
    }
    
    UINT32 bmSize = sizeof(INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER);
    if ((UINT32)bootPolicy.size() < localOffset + bmSize) {
        return U_INVALID_BG_BOOT_POLICY;
    }
    
    // Valid BPM found
    info = usprintf("LocalOffset: %08Xh, BP SVN: %02Xh, ACM SVN: %02Xh",
                    localOffset,
                    header->BPSVN,
                    header->ACMSVN);
    
    // Add BP header info
    securityInfo += usprintf("Intel BootGuard Boot Policy Manifest found at base %Xh\n"
                             "Tag: __ACBP__ Version: %02Xh HeaderVersion: %02Xh\n"
                             "PMBPMVersion: %02Xh PBSVN: %02Xh ACMSVN: %02Xh NEMDataStack: %04Xh\n",
                             model->base(parent) + localOffset,
                             header->Version,
                             header->HeaderVersion,
                             header->PMBPMVersion,
                             header->BPSVN,
                             header->ACMSVN,
                             header->NEMDataSize);
    
    // Iterate over elements to get them all
    UINT32 elementOffset = 0;
    UINT32 elementSize = 0;
    USTATUS status = findNextBootGuardBootPolicyElement(bootPolicy, localOffset + sizeof(INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_HEADER), elementOffset, elementSize);
    while (status == U_SUCCESS) {
        const UINT64* currentPos = (const UINT64*)(bootPolicy.constData() + elementOffset);
        if (*currentPos == INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_IBB_ELEMENT_TAG) {
            const INTEL_BOOT_GUARD_IBB_ELEMENT* elementHeader = (const INTEL_BOOT_GUARD_IBB_ELEMENT*)currentPos;
            // Valid IBB element found
            securityInfo += usprintf("\nInitial Boot Block Element found at base %Xh\n"
                                     "Tag: __IBBS__       Version: %02Xh\n"
                                     "Flags: %08Xh    IbbMchBar: %08Xh VtdBar: %08Xh\n"
                                     "PmrlBase: %08Xh PmrlLimit: %08Xh  EntryPoint: %08Xh",
                                     model->base(parent) + localOffset + elementOffset,
                                     elementHeader->Version,
                                     elementHeader->Flags,
                                     (UINT32)elementHeader->IbbMchBar,
                                     (UINT32)elementHeader->VtdBar,
                                     elementHeader->PmrlBase,
                                     elementHeader->PmrlLimit,
                                     elementHeader->EntryPoint);
            
            // Add PostIbbHash
            securityInfo += UString("\n\nPost IBB Hash:\n");
            for (UINT8 i = 0; i < sizeof(elementHeader->IbbHash.HashBuffer); i++) {
                securityInfo += usprintf("%02X", elementHeader->IbbHash.HashBuffer[i]);
            }
            
            // Check for non-empry PostIbbHash
            UByteArray postIbbHash((const char*)elementHeader->IbbHash.HashBuffer, sizeof(elementHeader->IbbHash.HashBuffer));
            if (postIbbHash.count('\x00') != postIbbHash.size() && postIbbHash.count('\xFF') != postIbbHash.size()) {
                PROTECTED_RANGE range = {};
                range.Type = PROTECTED_RANGE_INTEL_BOOT_GUARD_POST_IBB;
                range.Hash = postIbbHash;
                ffsParser->protectedRanges.push_back(range);
            }
            
            // Add Digest
            bgBpDigest = UByteArray((const char*)elementHeader->Digest.HashBuffer, sizeof(elementHeader->Digest.HashBuffer));
            securityInfo += UString("\n\nIBB Digest:\n");
            for (UINT8 i = 0; i < (UINT8)bgBpDigest.size(); i++) {
                securityInfo += usprintf("%02X", (UINT8)bgBpDigest.at(i));
            }
            
            // Add all IBB segments
            securityInfo += UString("\n\nIBB Segments:\n");
            const INTEL_BOOT_GUARD_IBB_SEGMENT_ELEMENT* segments = (const INTEL_BOOT_GUARD_IBB_SEGMENT_ELEMENT*)(elementHeader + 1);
            for (UINT8 i = 0; i < elementHeader->IbbSegCount; i++) {
                securityInfo += usprintf("Flags: %04Xh Address: %08Xh Size: %08Xh\n",
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
            securityInfo += usprintf("\nPlatform Manufacturer Data Element found at base %Xh\n"
                                     "Tag: __PMDA__ Version: %02Xh DataSize: %02Xh",
                                     model->base(parent) + localOffset + elementOffset,
                                     elementHeader->Version,
                                     elementHeader->DataSize);
            // Check for Microsoft PMDA hash data
            const PROTECTED_RANGE_MICROSOFT_PMDA_HEADER* pmdaHeader = (const PROTECTED_RANGE_MICROSOFT_PMDA_HEADER*)(elementHeader + 1);
            if (pmdaHeader->Version == PROTECTED_RANGE_MICROSOFT_PMDA_VERSION
                && elementHeader->DataSize == sizeof(PROTECTED_RANGE_MICROSOFT_PMDA_HEADER) + sizeof(PROTECTED_RANGE_MICROSOFT_PMDA_ENTRY)*pmdaHeader->NumEntries) {
                // Add entries
                securityInfo += UString("\nMicrosoft PMDA-based protected ranges:\n");
                const PROTECTED_RANGE_MICROSOFT_PMDA_ENTRY* entries = (const PROTECTED_RANGE_MICROSOFT_PMDA_ENTRY*)(pmdaHeader + 1);
                for (UINT32 i = 0; i < pmdaHeader->NumEntries; i++) {
                    
                    securityInfo += usprintf("Address: %08Xh Size: %08Xh\n", entries[i].Address, entries[i].Size);
                    securityInfo += UString("Hash: ");
                    for (UINT8 j = 0; j < sizeof(entries[i].Hash); j++) {
                        securityInfo += usprintf("%02X", entries[i].Hash[j]);
                    }
                    securityInfo += UString("\n");
                    
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
                    if (i % 32 == 0)
                        securityInfo += UString("\n");
                    securityInfo += usprintf("%02X", data[i]);
                }
                securityInfo += UString("\n");
            }
        }
        else if (*currentPos == INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT_TAG) {
            const INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT* elementHeader = (const INTEL_BOOT_GUARD_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT*)currentPos;
            securityInfo += usprintf("\nBoot Policy Signature Element found at base %Xh\n"
                                     "Tag: __PMSG__ Version: %02Xh",
                                     model->base(parent) + localOffset + elementOffset,
                                     elementHeader->Version);
            
            // Add PubKey
            securityInfo += usprintf("\n\nBoot Policy RSA Public Key (Exponent: %Xh):", elementHeader->KeySignature.PubKey.Exponent);
            for (UINT16 i = 0; i < sizeof(elementHeader->KeySignature.PubKey.Modulus); i++) {
                if (i % 32 == 0)
                    securityInfo += UString("\n");
                securityInfo += usprintf("%02X", elementHeader->KeySignature.PubKey.Modulus[i]);
            }
            
            // Calculate and add PubKey hash
            UINT8 hash[SHA256_HASH_SIZE];
            sha256(&elementHeader->KeySignature.PubKey.Modulus, sizeof(elementHeader->KeySignature.PubKey.Modulus), hash);
            securityInfo += UString("\n\nBoot Policy RSA Public Key Hash:");
            for (UINT8 i = 0; i < sizeof(hash); i++) {
                if (i % 32 == 0)
                    securityInfo += UString("\n");
                securityInfo += usprintf("%02X", hash[i]);
            }
            bgBpHash = UByteArray((const char*)hash, sizeof(hash));
            
            // Add Signature
            securityInfo += UString("\n\nBoot Policy RSA Signature:");
            for (UINT16 i = 0; i < sizeof(elementHeader->KeySignature.Signature.Signature); i++) {
                if (i % 32 == 0)
                    securityInfo += UString("\n");
                securityInfo += usprintf("%02X", elementHeader->KeySignature.Signature.Signature[i]);
            }
        }
        status = findNextBootGuardBootPolicyElement(bootPolicy, elementOffset + elementSize, elementOffset, elementSize);
    }
    
    securityInfo += UString("\n------------------------------------------------------------------------\n\n");
    bgBootPolicyFound = true;
    return U_SUCCESS;
}

#if 0 // Disable for now
USTATUS BGKeyManifestParser::ParseManifest(const QByteArray &keyManifest, const UINT32 localOffset, const QModelIndex &parent, QString &info, UINT32 &realSize, UString &securityInfo, TreeModel* model, UByteArray bgKmHash)
{
    U_UNUSED_PARAMETER(realSize);
    if ((UINT32)keyManifest.size() < localOffset + sizeof(BG_KEY_MANIFEST)) {
        return U_INVALID_BG_KEY_MANIFEST;
    }
    
    const BG_KEY_MANIFEST* header = (const BG_KEY_MANIFEST*)(keyManifest.constData() + localOffset);
    if (header->Tag != BG_KEY_MANIFEST_TAG) {
        return U_INVALID_BG_KEY_MANIFEST;
    }
    
    // Valid KM found
    info = usprintf("LocalOffset: %08Xh, KM Version: %02Xh, KM SVN: %02Xh, KM ID: %02Xh",
                    localOffset,
                    header->KmVersion,
                    header->KmSvn,
                    header->KmId
                    );
    
    // Add KM header info
    securityInfo += usprintf(
                             "Intel BootGuard Key manifest found at base %Xh\n"
                             "Tag: __KEYM__ Version: %02Xh KmVersion: %02Xh KmSvn: %02Xh KmId: %02Xh",
                             model->base(parent) + localOffset,
                             header->Version,
                             header->KmVersion,
                             header->KmSvn,
                             header->KmId
                             );
    
    // Add hash of Key Manifest PubKey, this hash will be written to FPFs
    UINT8 hash[SHA256_HASH_SIZE];
    sha256(&header->KeyManifestSignature.PubKey.Modulus, sizeof(header->KeyManifestSignature.PubKey.Modulus), hash);
    securityInfo += UString("\n\nKey Manifest RSA Public Key Hash:\n");
    for (UINT8 i = 0; i < sizeof(hash); i++) {
        securityInfo += usprintf("%02X", hash[i]);
    }
    
    // Add BpKeyHash
    securityInfo += UString("\n\nBoot Policy RSA Public Key Hash:\n");
    for (UINT8 i = 0; i < sizeof(header->BpKeyHash.HashBuffer); i++) {
        securityInfo += usprintf("%02X", header->BpKeyHash.HashBuffer[i]);
    }
    bgKmHash = UByteArray((const char*)header->BpKeyHash.HashBuffer, sizeof(header->BpKeyHash.HashBuffer));
    
    // Add Key Manifest PubKey
    securityInfo += usprintf("\n\nKey Manifest RSA Public Key (Exponent: %Xh):",
                             header->KeyManifestSignature.PubKey.Exponent);
    for (UINT16 i = 0; i < sizeof(header->KeyManifestSignature.PubKey.Modulus); i++) {
        if (i % 32 == 0)
            securityInfo += UString("\n");
        securityInfo += usprintf("%02X", header->KeyManifestSignature.PubKey.Modulus[i]);
    }
    // Add Key Manifest Signature
    securityInfo += UString("\n\nKey Manifest RSA Signature:");
    for (UINT16 i = 0; i < sizeof(header->KeyManifestSignature.Signature.Signature); i++) {
        if (i % 32 == 0)
            securityInfo += UString("\n");
        securityInfo += usprintf("%02X", header->KeyManifestSignature.Signature.Signature[i]);
    }
    securityInfo += UString("\n------------------------------------------------------------------------\n\n");
    
    return U_SUCCESS;
}


USTATUS BGKeyManifestParserIcelake::ParseManifest(const QByteArray &keyManifest, const UINT32 localOffset, const QModelIndex &parent, QString &info, UINT32 &realSize, UString &securityInfo, TreeModel* model, UByteArray bgKmHash)
{
    U_UNUSED_PARAMETER(realSize);
    if ((UINT32)keyManifest.size() < localOffset + sizeof(BG_KEY_MANIFEST2)) {
        return U_INVALID_BG_KEY_MANIFEST;
    }
    
    const BG_KEY_MANIFEST2* header = (const BG_KEY_MANIFEST2*)(keyManifest.constData() + localOffset);
    if (header->Tag != BG_KEY_MANIFEST_TAG) {
        return U_INVALID_BG_KEY_MANIFEST;
    }
    
    // Valid KM found
    info = usprintf("LocalOffset: %08Xh, KM Version: %02Xh, KM SVN: %02Xh, KM ID: %02Xh",
                    localOffset,
                    header->KmVersion,
                    header->KmSvn,
                    header->KmId);
    
    // Add KM header info
    securityInfo += usprintf("Intel BootGuard Key manifest found at base %Xh\n"
                             "Tag: __KEYM__ Version: %02Xh KmVersion: %02Xh KmSvn: %02Xh KmId: %02Xh TotalKeys: %02Xh SignatureOffset: %04Xh",
                             model->base(parent) + localOffset,
                             header->Version,
                             header->KmVersion,
                             header->KmSvn,
                             header->KmId,
                             header->TotalKeys,
                             header->RSAEntryOffset);
    
    // Add hash of Key Manifest PubKey, this hash will be written to FPFs
    UINT8 hash[SHA256_HASH_SIZE];
    sha256(&header->KeyManifestSignature.PubKey.Modulus, sizeof(header->KeyManifestSignature.PubKey.Modulus), hash);
    securityInfo += UString("\n\nKey Manifest RSA Public Key Hash:\n");
    for (UINT8 i = 0; i < sizeof(hash); i++) {
        securityInfo += usprintf("%02X", hash[i]);
    }
    
    // Add BpKeyHash
    securityInfo += UString("\n\nBoot Policy RSA Public Key Hash:\n");
    for (UINT8 i = 0; i < sizeof(header->BpKeyHash.HashBuffer); i++) {
        securityInfo += usprintf("%02X", header->BpKeyHash.HashBuffer[i]);
    }
    bgKmHash = UByteArray((const char*)header->BpKeyHash.HashBuffer, sizeof(header->BpKeyHash.HashBuffer));
    
    // Add Key Manifest PubKey
    securityInfo += usprintf("\n\nKey Manifest RSA Public Key (Exponent: %Xh):",
                             header->KeyManifestSignature.PubKey.Exponent);
    for (UINT16 i = 0; i < sizeof(header->KeyManifestSignature.PubKey.Modulus); i++) {
        if (i % 32 == 0)
            securityInfo += UString("\n");
        securityInfo += usprintf("%02X", header->KeyManifestSignature.PubKey.Modulus[i]);
    }
    // Add Key Manifest Signature
    securityInfo += UString("\n\nKey Manifest RSA Signature:");
    for (UINT16 i = 0; i < sizeof(header->KeyManifestSignature.Signature.Signature); i++) {
        if (i % 32 == 0)
            securityInfo += UString("\n");
        securityInfo += usprintf("%02X", header->KeyManifestSignature.Signature.Signature[i]);
    }
    securityInfo += UString("\n------------------------------------------------------------------------\n\n");
    
    return U_SUCCESS;
    
}

USTATUS BGIBBManifestParser::ParseManifest(const QByteArray &bootPolicy, const UINT32 localOffset, const QModelIndex &parent, QString &info, UINT32 &realSize, UString &securityInfo, TreeModel* model, UByteArray bgKmHash)
{
    U_UNUSED_PARAMETER(realSize);
    U_UNUSED_PARAMETER(bgKmHash);
    
    if ((UINT32)bootPolicy.size() < localOffset + sizeof(BG_BOOT_POLICY_MANIFEST_HEADER)) {
        return U_INVALID_BG_BOOT_POLICY;
    }
    
    const BG_BOOT_POLICY_MANIFEST_HEADER* header = (const BG_BOOT_POLICY_MANIFEST_HEADER*)(bootPolicy.constData() + localOffset);
    if (header->Tag != BG_BOOT_POLICY_MANIFEST_HEADER_TAG) {
        return U_INVALID_BG_BOOT_POLICY;
    }
    
    UINT32 bmSize = sizeof(BG_BOOT_POLICY_MANIFEST_HEADER);
    if ((UINT32)bootPolicy.size() < localOffset + bmSize) {
        return U_INVALID_BG_BOOT_POLICY;
    }
    
    // Valid BPM found
    info = usprintf("LocalOffset: %08Xh, BP SVN: %02Xh, ACM SVN: %02Xh",
                    localOffset,
                    header->BPSVN,
                    header->ACMSVN
                    );
    
    // Add BP header info
    securityInfo += usprintf(
                             "Intel BootGuard Boot Policy Manifest found at base %Xh\n"
                             "Tag: __ACBP__ Version: %02Xh HeaderVersion: %02Xh\n"
                             "PMBPMVersion: %02Xh PBSVN: %02Xh ACMSVN: %02Xh NEMDataStack: %04Xh\n",
                             model->base(parent) + localOffset,
                             header->Version,
                             header->HeaderVersion,
                             header->PMBPMVersion,
                             header->BPSVN,
                             header->ACMSVN,
                             header->NEMDataSize
                             );
    
    // Iterate over elements to get them all
    UINT32 elementOffset = 0;
    UINT32 elementSize = 0;
    USTATUS status = this->ffsParser->findNextBootGuardBootPolicyElement(bootPolicy, localOffset + sizeof(BG_BOOT_POLICY_MANIFEST_HEADER), elementOffset, elementSize);
    while (status == U_SUCCESS) {
        const UINT64* currentPos = (const UINT64*)(bootPolicy.constData() + elementOffset);
        if (*currentPos == BG_BOOT_POLICY_MANIFEST_IBB_ELEMENT_TAG) {
            const BG_IBB_ELEMENT* elementHeader = (const BG_IBB_ELEMENT*)currentPos;
            // Valid IBB element found
            securityInfo += usprintf(
                                     "\nInitial Boot Block Element found at base %Xh\n"
                                     "Tag: __IBBS__       Version: %02Xh\n"
                                     "Flags: %08Xh    IbbMchBar: %08Xh VtdBar: %08Xh\n"
                                     "PmrlBase: %08Xh PmrlLimit: %08Xh  EntryPoint: %08Xh",
                                     model->base(parent) + localOffset + elementOffset,
                                     elementHeader->Version,
                                     elementHeader->Flags,
                                     (UINT32)elementHeader->IbbMchBar,
                                     (UINT32)elementHeader->VtdBar,
                                     elementHeader->PmrlBase,
                                     elementHeader->PmrlLimit,
                                     elementHeader->EntryPoint
                                     );
            
            // Add PostIbbHash
            securityInfo += UString("\n\nPost IBB Hash:\n");
            for (UINT8 i = 0; i < sizeof(elementHeader->IbbHash.HashBuffer); i++) {
                securityInfo += usprintf("%02X", elementHeader->IbbHash.HashBuffer[i]);
            }
            
            // Check for non-empry PostIbbHash
            UByteArray postIbbHash((const char*)elementHeader->IbbHash.HashBuffer, sizeof(elementHeader->IbbHash.HashBuffer));
            if (postIbbHash.count('\x00') != postIbbHash.size() && postIbbHash.count('\xFF') != postIbbHash.size()) {
                BG_PROTECTED_RANGE range;
                range.Type = PROTECTED_RANGE_INTEL_BOOT_GUARD_POST_IBB;
                range.Hash = postIbbHash;
                this->ffsParser->bgProtectedRanges.push_back(range);
            }
            
            // Add Digest
            this->ffsParser->bgBpDigest = UByteArray((const char*)elementHeader->Digest.HashBuffer, sizeof(elementHeader->Digest.HashBuffer));
            securityInfo += UString("\n\nIBB Digest:\n");
            for (UINT8 i = 0; i < (UINT8)(this->ffsParser->bgBpDigest.size()); i++) {
                securityInfo += usprintf("%02X", (UINT8)(this->ffsParser->bgBpDigest).at(i));
            }
            
            // Add all IBB segments
            securityInfo += UString("\n\nIBB Segments:\n");
            const BG_IBB_SEGMENT_ELEMENT* segments = (const BG_IBB_SEGMENT_ELEMENT*)(elementHeader + 1);
            for (UINT8 i = 0; i < elementHeader->IbbSegCount; i++) {
                securityInfo += usprintf("Flags: %04Xh Address: %08Xh Size: %08Xh\n",
                                         segments[i].Flags, segments[i].Base, segments[i].Size);
                if (segments[i].Flags == BG_IBB_SEGMENT_FLAG_IBB) {
                    BG_PROTECTED_RANGE range;
                    range.Offset = segments[i].Base;
                    range.Size = segments[i].Size;
                    range.Type = PROTECTED_RANGE_INTEL_BOOT_GUARD_IBB;
                    this->ffsParser->bgProtectedRanges.push_back(range);
                }
            }
        }
        else if (*currentPos == BG_BOOT_POLICY_MANIFEST_PLATFORM_MANUFACTURER_ELEMENT_TAG) {
            const BG_PLATFORM_MANUFACTURER_ELEMENT* elementHeader = (const BG_PLATFORM_MANUFACTURER_ELEMENT*)currentPos;
            securityInfo += usprintf(
                                     "\nPlatform Manufacturer Data Element found at base %Xh\n"
                                     "Tag: __PMDA__ Version: %02Xh DataSize: %02Xh",
                                     model->base(parent) + localOffset + elementOffset,
                                     elementHeader->Version,
                                     elementHeader->DataSize
                                     );
            // Check for Microsoft PMDA hash data
            const BG_MICROSOFT_PMDA_HEADER* pmdaHeader = (const BG_MICROSOFT_PMDA_HEADER*)(elementHeader + 1);
            if (pmdaHeader->Version == BG_MICROSOFT_PMDA_VERSION
                && elementHeader->DataSize == sizeof(BG_MICROSOFT_PMDA_HEADER) + sizeof(BG_MICROSOFT_PMDA_ENTRY)*pmdaHeader->NumEntries) {
                // Add entries
                securityInfo += UString("\nMicrosoft PMDA-based protected ranges:\n");
                const BG_MICROSOFT_PMDA_ENTRY* entries = (const BG_MICROSOFT_PMDA_ENTRY*)(pmdaHeader + 1);
                for (UINT32 i = 0; i < pmdaHeader->NumEntries; i++) {
                    
                    securityInfo += usprintf("Address: %08Xh Size: %08Xh\n", entries[i].Address, entries[i].Size);
                    securityInfo += UString("Hash: ");
                    for (UINT8 j = 0; j < sizeof(entries[i].Hash); j++) {
                        securityInfo += usprintf("%02X", entries[i].Hash[j]);
                    }
                    securityInfo += UString("\n");
                    
                    BG_PROTECTED_RANGE range;
                    range.Offset = entries[i].Address;
                    range.Size = entries[i].Size;
                    range.Hash = UByteArray((const char*)entries[i].Hash, sizeof(entries[i].Hash));
                    range.Type = PROTECTED_RANGE_VENDOR_HASH_MICROSOFT;
                    this->ffsParser->bgProtectedRanges.push_back(range);
                }
            }
            else {
                // Add raw data
                const UINT8* data = (const UINT8*)(elementHeader + 1);
                for (UINT16 i = 0; i < elementHeader->DataSize; i++) {
                    if (i % 32 == 0)
                        securityInfo += UString("\n");
                    securityInfo += usprintf("%02X", data[i]);
                }
                securityInfo += UString("\n");
            }
        }
        else if (*currentPos == BG_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT_TAG) {
            const BG_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT* elementHeader = (const BG_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT*)currentPos;
            securityInfo += usprintf(
                                     "\nBoot Policy Signature Element found at base %Xh\n"
                                     "Tag: __PMSG__ Version: %02Xh",
                                     model->base(parent) + localOffset + elementOffset,
                                     elementHeader->Version
                                     );
            
            // Add PubKey
            securityInfo += usprintf("\n\nBoot Policy RSA Public Key (Exponent: %Xh):", elementHeader->KeySignature.PubKey.Exponent);
            for (UINT16 i = 0; i < sizeof(elementHeader->KeySignature.PubKey.Modulus); i++) {
                if (i % 32 == 0)
                    securityInfo += UString("\n");
                securityInfo += usprintf("%02X", elementHeader->KeySignature.PubKey.Modulus[i]);
            }
            
            // Calculate and add PubKey hash
            UINT8 hash[SHA256_HASH_SIZE];
            sha256(&elementHeader->KeySignature.PubKey.Modulus, sizeof(elementHeader->KeySignature.PubKey.Modulus), hash);
            securityInfo += UString("\n\nBoot Policy RSA Public Key Hash:");
            for (UINT8 i = 0; i < sizeof(hash); i++) {
                if (i % 32 == 0)
                    securityInfo += UString("\n");
                securityInfo += usprintf("%02X", hash[i]);
            }
            this->ffsParser->bgBpHash = UByteArray((const char*)hash, sizeof(hash));
            
            // Add Signature
            securityInfo += UString("\n\nBoot Policy RSA Signature:");
            for (UINT16 i = 0; i < sizeof(elementHeader->KeySignature.Signature.Signature); i++) {
                if (i % 32 == 0)
                    securityInfo += UString("\n");
                securityInfo += usprintf("%02X", elementHeader->KeySignature.Signature.Signature[i]);
            }
        }
        status = this->ffsParser->findNextBootGuardBootPolicyElement(bootPolicy, elementOffset + elementSize, elementOffset, elementSize);
    }
    
    securityInfo += UString("\n------------------------------------------------------------------------\n\n");
    this->ffsParser->bgBootPolicyFound = true;
    return U_SUCCESS;
}

USTATUS BGIBBManifestParserIcelake::ParseManifest(const QByteArray &bootPolicy, const UINT32 localOffset, const QModelIndex &parent, QString &info, UINT32 &realSize, UString &securityInfo, TreeModel* model, UByteArray bgKmHash)
{
    U_UNUSED_PARAMETER(realSize);
    U_UNUSED_PARAMETER(bgKmHash);
    
    if ((UINT32)bootPolicy.size() < localOffset + sizeof(BG_BOOT_POLICY_MANIFEST_HEADER2)) {
        return U_INVALID_BG_BOOT_POLICY;
    }
    
    const BG_BOOT_POLICY_MANIFEST_HEADER2* header = (const BG_BOOT_POLICY_MANIFEST_HEADER2*)(bootPolicy.constData() + localOffset);
    if (header->Tag != BG_BOOT_POLICY_MANIFEST_HEADER_TAG) {
        return U_INVALID_BG_BOOT_POLICY;
    }
    
    UINT32 bmSize = sizeof(BG_BOOT_POLICY_MANIFEST_HEADER2);
    if ((UINT32)bootPolicy.size() < localOffset + bmSize) {
        return U_INVALID_BG_BOOT_POLICY;
    }
    
    // Valid BPM found
    info = usprintf("LocalOffset: %08Xh, BP SVN: %02Xh, ACM SVN: %02Xh",
                    localOffset,
                    header->BPSVN,
                    header->ACMSVN
                    );
    
    // Add BP header info
    securityInfo += usprintf(
                             "Intel BootGuard Boot Policy Manifest found at base %Xh\n"
                             "Tag: __ACBP__ Version: %02Xh HeaderVersion: %02Xh\n"
                             "PMBPMVersion: %02Xh PBSVN: %02Xh ACMSVN: %02Xh SignatureOffset: %04Xh NEMDataStack: %04Xh\n",
                             model->base(parent) + localOffset,
                             header->Version,
                             header->HeaderVersion,
                             header->PMBPMVersion,
                             header->BPSVN,
                             header->ACMSVN,
                             header->RSAEntryOffset,
                             header->NEMDataSize
                             );
    
    // Iterate over elements to get them all
    UINT32 elementOffset = 0;
    UINT32 elementSize = 0;
    USTATUS status = this->ffsParser->findNextBootGuardBootPolicyElement(bootPolicy, localOffset + sizeof(BG_BOOT_POLICY_MANIFEST_HEADER2), elementOffset, elementSize);
    while (status == U_SUCCESS) {
        const UINT64* currentPos = (const UINT64*)(bootPolicy.constData() + elementOffset);
        if (*currentPos == BG_BOOT_POLICY_MANIFEST_IBB_ELEMENT_TAG)
        {
            const BG_IBB_ELEMENT2* elementHeader = (const BG_IBB_ELEMENT2*)currentPos;
            // Valid IBB element found
            securityInfo += usprintf(
                                     "\nInitial Boot Block Element found at base %Xh\n"
                                     "Tag: __IBBS__  Version: %02Xh  ProfileTimer: %02Xh  ElementSize: %04Xh\n"
                                     "Flags: %08Xh    IbbMchBar: %08Xh VtdBar: %08Xh\n"
                                     "PmrlBase: %08Xh PmrlLimit: %08Xh  EntryPoint: %08Xh",
                                     model->base(parent) + localOffset + elementOffset,
                                     elementHeader->Version,
                                     elementHeader->PolicyTimerVal,
                                     elementHeader->ElementSize,
                                     elementHeader->Flags,
                                     (UINT32)elementHeader->IbbMchBar,
                                     (UINT32)elementHeader->VtdBar,
                                     elementHeader->PmrlBase,
                                     elementHeader->PmrlLimit,
                                     elementHeader->EntryPoint
                                     );
            
            // Add PostIbbHash
            //post Ibb hash location not exists
            
            // Add Digest
            securityInfo += UString("\n\nIBB Digests:\n");
            char* currSHA = (char*)(elementHeader + 1);
            for (int i=0; i < elementHeader->NumOfDigests; i++)
            {
                if (((BG_HASH_HEADER*)currSHA)->HashAlgorithmId == 0xB)
                    securityInfo += usprintf("\n%02X- SHA256 Hash:\n", i+1);
                else if (((BG_HASH_HEADER*)currSHA)->HashAlgorithmId == 0xC)
                    securityInfo += usprintf("\n%02X- SHA384 Hash:\n", i+1);
                else if (((BG_HASH_HEADER*)currSHA)->HashAlgorithmId == 0x4)
                    securityInfo += usprintf("\n%02X- SHA1 Hash:\n", i+1);
                else
                    securityInfo += usprintf("\n%02X- Unknown Hash:\n", i+1);
                
                UINT16 currSHASize = ((BG_HASH_HEADER*)currSHA)->Size;
                this->ffsParser->bgBpDigest= UByteArray((const char*)(currSHA+sizeof(BG_HASH_HEADER)), currSHASize);
                for (UINT8 i = 0; i < (UINT8)this->ffsParser->bgBpDigest.size(); i++)
                    securityInfo += usprintf("%02X", (UINT8)this->ffsParser->bgBpDigest.at(i));
                
                currSHA = currSHA + sizeof(BG_HASH_HEADER) + currSHASize;
            }
            
            
            // Add all IBB segments
            securityInfo += UString("\n\nIBB Segments:\n");
            const BG_IBB_SEGMENT_ELEMENT* segments = (const BG_IBB_SEGMENT_ELEMENT*)((char*)elementHeader + sizeof(BG_IBB_ELEMENT2) + elementHeader->SizeOfDigests +3);
            UINT8 IbbSegCount = *((char*)segments -1);
            for (UINT8 i = 0; i < IbbSegCount; i++) {
                securityInfo += usprintf("Flags: %04Xh Address: %08Xh Size: %08Xh\n",
                                         segments[i].Flags, segments[i].Base, segments[i].Size);
                if (segments[i].Flags == BG_IBB_SEGMENT_FLAG_IBB) {
                    BG_PROTECTED_RANGE range;
                    range.Offset = segments[i].Base;
                    range.Size = segments[i].Size;
                    range.Type = PROTECTED_RANGE_INTEL_BOOT_GUARD_IBB;
                    this->ffsParser->bgProtectedRanges.push_back(range);
                }
            }
        }
        else if (*currentPos == BG_BOOT_POLICY_MANIFEST_PLATFORM_MANUFACTURER_ELEMENT_TAG) {
            const BG_PLATFORM_MANUFACTURER_ELEMENT* elementHeader = (const BG_PLATFORM_MANUFACTURER_ELEMENT*)currentPos;
            securityInfo += usprintf(
                                     "\nPlatform Manufacturer Data Element found at base %Xh\n"
                                     "Tag: __PMDA__ Version: %02Xh DataSize: %02Xh",
                                     model->base(parent) + localOffset + elementOffset,
                                     elementHeader->Version,
                                     elementHeader->DataSize
                                     );
            // Check for Microsoft PMDA hash data
            const BG_MICROSOFT_PMDA_HEADER* pmdaHeader = (const BG_MICROSOFT_PMDA_HEADER*)(elementHeader + 1);
            if (pmdaHeader->Version == BG_MICROSOFT_PMDA_VERSION
                && elementHeader->DataSize == sizeof(BG_MICROSOFT_PMDA_HEADER) + sizeof(BG_MICROSOFT_PMDA_ENTRY)*pmdaHeader->NumEntries) {
                // Add entries
                securityInfo += UString("\nMicrosoft PMDA-based protected ranges:\n");
                const BG_MICROSOFT_PMDA_ENTRY* entries = (const BG_MICROSOFT_PMDA_ENTRY*)(pmdaHeader + 1);
                for (UINT32 i = 0; i < pmdaHeader->NumEntries; i++) {
                    
                    securityInfo += usprintf("Address: %08Xh Size: %08Xh\n", entries[i].Address, entries[i].Size);
                    securityInfo += UString("Hash: ");
                    for (UINT8 j = 0; j < sizeof(entries[i].Hash); j++) {
                        securityInfo += usprintf("%02X", entries[i].Hash[j]);
                    }
                    securityInfo += UString("\n");
                    
                    BG_PROTECTED_RANGE range;
                    range.Offset = entries[i].Address;
                    range.Size = entries[i].Size;
                    range.Hash = UByteArray((const char*)entries[i].Hash, sizeof(entries[i].Hash));
                    range.Type = PROTECTED_RANGE_VENDOR_HASH_MICROSOFT;
                    this->ffsParser->bgProtectedRanges.push_back(range);
                }
            }
            else {
                // Add raw data
                const UINT8* data = (const UINT8*)(elementHeader + 1);
                for (UINT16 i = 0; i < elementHeader->DataSize; i++) {
                    if (i % 32 == 0)
                        securityInfo += UString("\n");
                    securityInfo += usprintf("%02X", data[i]);
                }
                securityInfo += UString("\n");
            }
        }
        else if (*currentPos == BG_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT_TAG) {
            const BG_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT2* elementHeader = (const BG_BOOT_POLICY_MANIFEST_SIGNATURE_ELEMENT2*)currentPos;
            securityInfo += usprintf(
                                     "\nBoot Policy Signature Element found at base %Xh\n"
                                     "Tag: __PMSG__ Version: %02Xh",
                                     model->base(parent) + localOffset + elementOffset,
                                     elementHeader->Version
                                     );
            
            // Add PubKey
            securityInfo += usprintf("\n\nBoot Policy RSA Public Key (Exponent: %Xh):", elementHeader->KeySignature.PubKey.Exponent);
            for (UINT16 i = 0; i < sizeof(elementHeader->KeySignature.PubKey.Modulus); i++) {
                if (i % 32 == 0)
                    securityInfo += UString("\n");
                securityInfo += usprintf("%02X", elementHeader->KeySignature.PubKey.Modulus[i]);
            }
            
            // Calculate and add PubKey hash
            UINT8 hash[SHA256_HASH_SIZE];
            sha256(&elementHeader->KeySignature.PubKey.Modulus, sizeof(elementHeader->KeySignature.PubKey.Modulus), hash);
            securityInfo += UString("\n\nBoot Policy RSA Public Key Hash:");
            for (UINT8 i = 0; i < sizeof(hash); i++) {
                if (i % 32 == 0)
                    securityInfo += UString("\n");
                securityInfo += usprintf("%02X", hash[i]);
            }
            this->ffsParser->bgBpHash = UByteArray((const char*)hash, sizeof(hash));
            
            // Add Signature
            securityInfo += UString("\n\nBoot Policy RSA Signature:");
            for (UINT16 i = 0; i < sizeof(elementHeader->KeySignature.Signature.Signature); i++) {
                if (i % 32 == 0)
                    securityInfo += UString("\n");
                securityInfo += usprintf("%02X", elementHeader->KeySignature.Signature.Signature[i]);
            }
        }
        status = this->ffsParser->findNextBootGuardBootPolicyElement(bootPolicy, elementOffset + elementSize, elementOffset, elementSize);
    }
    
    securityInfo += UString("\n------------------------------------------------------------------------\n\n");
    this->ffsParser->bgBootPolicyFound = true;
    return U_SUCCESS;
}
#endif
