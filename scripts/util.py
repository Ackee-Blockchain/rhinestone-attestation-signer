from wake.deployment import *
import json
from pathlib import Path

from dataclasses import dataclass
from typing import List, Optional

from dataclasses import dataclass
from enum import Enum


@dataclass
class Auditor:
    name: str
    uri: str
    authors: List[str]


class ERC7579ModuleType(Enum):
    NONE = 0
    VALIDATOR = 1
    EXECUTOR = 2
    FALLBACK = 3
    HOOK = 4


@dataclass
class ModuleTypeAttributes:
    moduleType: ERC7579ModuleType
    encodedAttributes: bytes


@dataclass
class ModuleTypeAttributesData:
    moduleType: uint8
    encodedAttributes: bytes


@dataclass
class ModuleAttributes:
    moduleAddress: Address
    packedAttributes: bytes
    typeAttributes: List[ModuleTypeAttributes]
    packedExternalDependency: bytes
    ercDeps: List[uint16]


@dataclass
class ModuleAttributesData:
    moduleAddress: Address
    packedAttributes: bytes
    typeAttributes: List[ModuleTypeAttributesData]
    packedExternalDependency: bytes
    ercDeps: List[uint16]


class SignatureType(Enum):
    NONE = 0
    SECP256K1 = 1
    ERC1271 = 2


@dataclass
class Signature:
    sigType: SignatureType
    signer: Address
    signatureData: bytes
    hash: bytes32


@dataclass
class SignatureData:
    sigType: uint8
    signer: Address
    signatureData: bytes
    hash: bytes32


@dataclass
class AuditSummary:
    title: str
    auditor: Auditor
    module_attributes: ModuleAttributesData
    signature: SignatureData

    @dataclass
    class Digest:
        title: str
        auditor: Auditor
        moduleAttributes: ModuleAttributes

    def encode(self) -> bytes:
        data = self.Digest(
            title=self.title,
            auditor=self.auditor,
            moduleAttributes=self.module_attributes,
        )
        return abi.encode(data)


@dataclass
class JsonValidatorAttributes:
    unscopedValidator: bool
    recoveryModule: bool
    multiplexer: bool

    def pack(self) -> bytes:
        return bytes(
            [
                uint8(self.unscopedValidator),
                uint8(self.recoveryModule),
                uint8(self.multiplexer),
            ]
        )


@dataclass
class JsonFallbackAttributes:
    compatibilityFeature: bool
    callbacks: bool

    def pack(self) -> bytes:
        return bytes([uint8(self.compatibilityFeature), uint8(self.callbacks)])


@dataclass
class JsonExecutorAttributes:
    handlesUserAssets: bool
    delegateCall: bool
    triggeredByAccount: bool
    triggeredByRelayer: bool
    deterministicExecution: bool

    def pack(self) -> bytes:
        return bytes(
            [
                uint8(self.handlesUserAssets),
                uint8(self.delegateCall),
                uint8(self.triggeredByAccount),
                uint8(self.triggeredByRelayer),
                uint8(self.deterministicExecution),
            ]
        )


@dataclass
class JsonHookAttributes:
    defaultAllow: bool
    defaultDeny: bool
    accessControl: bool
    moduleControl: bool
    userControl: bool

    def pack(self) -> bytes:
        return bytes(
            [
                uint8(self.defaultAllow),
                uint8(self.defaultDeny),
                uint8(self.accessControl),
                uint8(self.moduleControl),
                uint8(self.userControl),
            ]
        )


@dataclass
class JsonGlobalAttributes:
    reentrancyProtection: bool
    importantDataValidation: bool
    inputManipulationProtection: bool
    emitsEvents: bool
    moduleOwnerCantRug: bool
    upgradeable: bool
    pausable: bool
    licensedModule: bool
    erc7562StorageCompliant: bool
    uninstallCleanUp: bool
    multichainCompatible: bool

    def pack(self) -> bytes:
        return bytes(
            [
                uint8(self.reentrancyProtection),
                uint8(self.importantDataValidation),
                uint8(self.inputManipulationProtection),
                uint8(self.emitsEvents),
                uint8(self.moduleOwnerCantRug),
                uint8(self.upgradeable),
                uint8(self.pausable),
                uint8(self.licensedModule),
                uint8(self.erc7562StorageCompliant),
                uint8(self.uninstallCleanUp),
                uint8(self.multichainCompatible),
            ]
        )


@dataclass
class JsonExternalDependency:
    oracle: bool
    bridges: bool
    dexs: bool
    vaults: bool
    registry: bool
    lending: bool
    liquidityProvision: bool
    governance: bool
    privacy: bool
    zkProvers: bool
    ercDeps: List[int]

    def pack(self) -> bytes:
        return bytes(
            [
                uint8(self.oracle),
                uint8(self.bridges),
                uint8(self.dexs),
                uint8(self.vaults),
                uint8(self.registry),
                uint8(self.lending),
                uint8(self.liquidityProvision),
                uint8(self.governance),
                uint8(self.privacy),
                uint8(self.zkProvers),
            ]
        )


@dataclass
class ModuleAttributes:
    moduleAddress: Address
    packedAttributes: bytes
    typeAttributes: List[ModuleTypeAttributes]
    packedExternalDependency: bytes
    ercDeps: List[uint16]


@dataclass
class ModuleAttributesData:
    moduleAddress: Address
    packedAttributes: bytes
    typeAttributes: List[ModuleTypeAttributesData]
    packedExternalDependency: bytes
    ercDeps: List[uint16]


@dataclass
class JsonModuleAttributes:
    moduleAddress: Address
    globalAttributes: JsonGlobalAttributes
    validatorAttributes: JsonValidatorAttributes
    executorAttributes: JsonExecutorAttributes
    fallbackAttributes: JsonFallbackAttributes
    hookAttributes: JsonHookAttributes
    externalDependency: JsonExternalDependency

    def encode(self) -> ModuleAttributesData:
        assert isinstance(self.moduleAddress, Address)
        return ModuleAttributesData(
            moduleAddress=self.moduleAddress,
            packedAttributes=self.globalAttributes.pack(),
            typeAttributes=[
                ModuleTypeAttributesData(
                    moduleType=uint8(ERC7579ModuleType.VALIDATOR.value),
                    encodedAttributes=self.validatorAttributes.pack(),
                ),
                ModuleTypeAttributesData(
                    moduleType=uint8(ERC7579ModuleType.EXECUTOR.value),
                    encodedAttributes=self.executorAttributes.pack(),
                ),
                ModuleTypeAttributesData(
                    moduleType=uint8(ERC7579ModuleType.FALLBACK.value),
                    encodedAttributes=self.fallbackAttributes.pack(),
                ),
                ModuleTypeAttributesData(
                    moduleType=uint8(ERC7579ModuleType.HOOK.value),
                    encodedAttributes=self.hookAttributes.pack(),
                ),
            ],
            packedExternalDependency=self.externalDependency.pack(),
            ercDeps=self.externalDependency.ercDeps,
        )


@dataclass
class Input:
    title: str
    auditor: Auditor
    reportUrl: str
    signer: Address
    moduleAttributes: JsonModuleAttributes
    signature: Optional[Signature] = None


def sign_file(path, acc: Account):
    print(path)
    json_file_path = Path(path)

    with open(json_file_path, "r") as f:
        file_data = json.load(f)

    # Parse the JSON data into Python class objects
    input_data = Input(**file_data)

    # Access the parsed data
    structured_data = input_data
    structured_data.signer = Address(structured_data.signer)
    structured_data.moduleAttributes = JsonModuleAttributes(
        **structured_data.moduleAttributes
    )
    structured_data.moduleAttributes.moduleAddress = Address(
        structured_data.moduleAttributes.moduleAddress
    )
    structured_data.moduleAttributes.validatorAttributes = JsonValidatorAttributes(
        **structured_data.moduleAttributes.validatorAttributes
    )
    structured_data.moduleAttributes.executorAttributes = JsonExecutorAttributes(
        **structured_data.moduleAttributes.executorAttributes
    )
    structured_data.moduleAttributes.fallbackAttributes = JsonFallbackAttributes(
        **structured_data.moduleAttributes.fallbackAttributes
    )
    structured_data.moduleAttributes.hookAttributes = JsonHookAttributes(
        **structured_data.moduleAttributes.hookAttributes
    )
    structured_data.moduleAttributes.externalDependency = JsonExternalDependency(
        **structured_data.moduleAttributes.externalDependency
    )

    structured_data.auditor = Auditor(**structured_data.auditor)

    structured_data.moduleAttributes.globalAttributes = JsonGlobalAttributes(
        **structured_data.moduleAttributes.globalAttributes
    )

    structured_sig = Signature(
        sigType=SignatureType.SECP256K1,
        signer=structured_data.signer,
        signatureData=b"",
        hash=bytes(32),
    )

    summary: AuditSummary = AuditSummary(
        title=input_data.title,
        auditor=structured_data.auditor,
        module_attributes=structured_data.moduleAttributes.encode(),
        signature=SignatureData(
            sigType=uint8(structured_sig.sigType.value),
            signer=structured_sig.signer,
            signatureData=structured_sig.signatureData,
            hash=structured_sig.hash,
        ),
    )

    encoded_digest = summary.encode()
    actual_hash = keccak256(encoded_digest)
    summary.signature.hash = actual_hash

    data = acc.sign(actual_hash)

    print("hash: ")
    print(actual_hash.hex())

    r = data[:32]
    s = data[32:64]
    v = uint8(int(data[64]))
    v = uint8(v - 27)
    summary.signature.signatureData = abi.encode_packed(r, s, v)
    # summary.signature.signatureData = data
    print("signature: ")
    print(summary.signature.signatureData.hex())

    # Step 2: Update only the signature and hash fields
    file_data["signature"]["signature"] = "0x" + summary.signature.signatureData.hex()
    file_data["signature"]["hash"] = "0x" + actual_hash.hex()

    file_path = Path("signed_" + path)
    import os

    os.makedirs(file_path.parent, exist_ok=True)
    # Step 3: Write the updated data back to the JSON file
    with open(file_path, "w") as json_file:
        json.dump(file_data, json_file, indent=2, ensure_ascii=False)
