// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors
#pragma once
#include <nlohmann/json.hpp>

namespace pcie_device
{
// clang-format off

enum class PCIeTypes{
    Invalid,
    Gen1,
    Gen2,
    Gen3,
    Gen4,
    Gen5,
    Gen6,
};

enum class DeviceType{
    Invalid,
    SingleFunction,
    MultiFunction,
    Simulated,
    Retimer,
};

enum class SlotType{
    Invalid,
    FullLength,
    HalfLength,
    LowProfile,
    Mini,
    M2,
    OEM,
    OCP3Small,
    OCP3Large,
    U2,
    EDSFF,
};

enum class LaneSplittingType{
    Invalid,
    None,
    Bridged,
    Bifurcated,
};

enum class CXLDeviceType{
    Invalid,
    Type1,
    Type2,
    Type3,
};

enum class CXLDynamicCapacityPolicies{
    Invalid,
    Free,
    Contiguous,
    Prescriptive,
    TagBased,
};

enum class CXLProtocolVersion{
    Invalid,
    CXL1_1,
    CXL2_0,
    CXL3_0,
    CXL3_1,
    CXL3_2,
};

NLOHMANN_JSON_SERIALIZE_ENUM(PCIeTypes, {
    {PCIeTypes::Invalid, "Invalid"},
    {PCIeTypes::Gen1, "Gen1"},
    {PCIeTypes::Gen2, "Gen2"},
    {PCIeTypes::Gen3, "Gen3"},
    {PCIeTypes::Gen4, "Gen4"},
    {PCIeTypes::Gen5, "Gen5"},
    {PCIeTypes::Gen6, "Gen6"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(DeviceType, {
    {DeviceType::Invalid, "Invalid"},
    {DeviceType::SingleFunction, "SingleFunction"},
    {DeviceType::MultiFunction, "MultiFunction"},
    {DeviceType::Simulated, "Simulated"},
    {DeviceType::Retimer, "Retimer"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(SlotType, {
    {SlotType::Invalid, "Invalid"},
    {SlotType::FullLength, "FullLength"},
    {SlotType::HalfLength, "HalfLength"},
    {SlotType::LowProfile, "LowProfile"},
    {SlotType::Mini, "Mini"},
    {SlotType::M2, "M2"},
    {SlotType::OEM, "OEM"},
    {SlotType::OCP3Small, "OCP3Small"},
    {SlotType::OCP3Large, "OCP3Large"},
    {SlotType::U2, "U2"},
    {SlotType::EDSFF, "EDSFF"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(LaneSplittingType, {
    {LaneSplittingType::Invalid, "Invalid"},
    {LaneSplittingType::None, "None"},
    {LaneSplittingType::Bridged, "Bridged"},
    {LaneSplittingType::Bifurcated, "Bifurcated"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(CXLDeviceType, {
    {CXLDeviceType::Invalid, "Invalid"},
    {CXLDeviceType::Type1, "Type1"},
    {CXLDeviceType::Type2, "Type2"},
    {CXLDeviceType::Type3, "Type3"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(CXLDynamicCapacityPolicies, {
    {CXLDynamicCapacityPolicies::Invalid, "Invalid"},
    {CXLDynamicCapacityPolicies::Free, "Free"},
    {CXLDynamicCapacityPolicies::Contiguous, "Contiguous"},
    {CXLDynamicCapacityPolicies::Prescriptive, "Prescriptive"},
    {CXLDynamicCapacityPolicies::TagBased, "TagBased"},
});

NLOHMANN_JSON_SERIALIZE_ENUM(CXLProtocolVersion, {
    {CXLProtocolVersion::Invalid, "Invalid"},
    {CXLProtocolVersion::CXL1_1, "CXL1_1"},
    {CXLProtocolVersion::CXL2_0, "CXL2_0"},
    {CXLProtocolVersion::CXL3_0, "CXL3_0"},
    {CXLProtocolVersion::CXL3_1, "CXL3_1"},
    {CXLProtocolVersion::CXL3_2, "CXL3_2"},
});

}
// clang-format on
