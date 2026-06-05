// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedUserOperation} from "./interfaces/PackedUserOperation.sol";
import {IAccount, ValidationData, ValidAfter, ValidUntil, parseValidationData} from "./interfaces/IAccount.sol";
import {IEntryPoint} from "./interfaces/IEntryPoint.sol";
import {IAccountExecute} from "./interfaces/IAccountExecute.sol";
import {IERC7579Account} from "./interfaces/IERC7579Account.sol";
import {ModuleLib} from "./utils/ModuleLib.sol";
import {
    ValidationManager,
    ValidationMode,
    ValidationId,
    ValidatorLib,
    ValidationType,
    PermissionId,
    PassFlag,
    SKIP_SIGNATURE
} from "./core/ValidationManager.sol";
import {IModule, IValidator, IHook, IExecutor, IFallback, IPolicy, ISigner} from "./interfaces/IERC7579Modules.sol";
import {EIP712} from "solady/utils/EIP712.sol";
import {ExecLib} from "./utils/ExecLib.sol";
import {ExecMode, CallType, ExecType, ExecModeSelector, ExecModePayload} from "./types/Types.sol";
import {
    CALLTYPE_SINGLE,
    CALLTYPE_DELEGATECALL,
    ERC1967_IMPLEMENTATION_SLOT,
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    VALIDATION_TYPE_7702,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    HOOK_MODULE_NOT_INSTALLED,
    HOOK_MODULE_INSTALLED,
    HOOK_ONLY_ENTRYPOINT,
    EXECTYPE_TRY,
    EXECTYPE_DEFAULT,
    EXEC_MODE_DEFAULT,
    CALLTYPE_DELEGATECALL,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    CALLTYPE_STATIC,
    MAGIC_VALUE_SIG_REPLAYABLE,
    ERC1271_INVALID,
    ERC1271_MAGICVALUE,
    EIP7702_PREFIX
} from "./types/Constants.sol";

import {InstallExecutorDataFormat, InstallFallbackDataFormat, InstallValidatorDataFormat} from "./types/Structs.sol";

contract Kernel is IAccount, IAccountExecute, IERC7579Account, ValidationManager {
    error ExecutionReverted();
    error InvalidExecutor();
    error InvalidFallback();
    error InvalidCallType();
    error OnlyExecuteUserOp();
    error InvalidModuleType();
    error InvalidCaller();
    error InvalidSelector();
    error InitConfigError(uint256 idx);
    error AlreadyInitialized();

    event Received(address sender, uint256 amount);
    event Upgraded(address indexed implementation);

    IEntryPoint public immutable entrypoint;

    // NOTE : when eip 1153 has been enabled, this can be transient storage
    mapping(bytes32 userOpHash => IHook) internal executionHook;

    constructor(IEntryPoint _entrypoint) {
        entrypoint = _entrypoint;
        _validationStorage().rootValidator = ValidationId.wrap(bytes21(abi.encodePacked(hex"deadbeef")));
    }

    modifier onlyEntryPoint() {
        if (msg.sender != address(entrypoint)) {
            revert InvalidCaller();
        }
        _;
    }

    modifier onlyEntryPointOrSelfOrRoot() {
        if (
            msg.sender != address(entrypoint) && msg.sender != address(this) // do rootValidator hook
        ) {
            IValidator validator = ValidatorLib.getValidator(_validationStorage().rootValidator);
            if (validator.isModuleType(4)) {
                bytes memory ret = IHook(address(validator)).preCheck(msg.sender, msg.value, msg.data);
                _;
                IHook(address(validator)).postCheck(ret);
            } else {
                revert InvalidCaller();
            }
        } else {
            _;
        }
    }

    function initialize(
        ValidationId _rootValidator,
        IHook hook,
        bytes calldata validatorData,
        bytes calldata hookData,
        bytes[] calldata initConfig
    ) external {
        ValidationStorage storage vs = _validationStorage();
        if (ValidationId.unwrap(vs.rootValidator) != bytes21(0) || bytes3(address(this).code) == EIP7702_PREFIX) {
            revert AlreadyInitialized();
        }
        if (ValidationId.unwrap(_rootValidator) == bytes21(0)) {
            revert InvalidValidator();
        }
        ValidationType vType = ValidatorLib.getType(_rootValidator);
        if (vType != VALIDATION_TYPE_VALIDATOR && vType != VALIDATION_TYPE_PERMISSION) {
            revert InvalidValidationType();
        }
        _setRootValidator(_rootValidator);
        ValidationConfig memory config = ValidationConfig({nonce: uint32(1), hook: hook});
        vs.currentNonce = 1;
        _installValidation(_rootValidator, config, validatorData, hookData);
        for (uint256 i = 0; i < initConfig.length; i++) {
            (bool success,) = address(this).call(initConfig[i]);
            if (!success) {
                revert InitConfigError(i);
            }
        }
    }

    function changeRootValidator(
        ValidationId _rootValidator,
        IHook hook,
        bytes calldata validatorData,
        bytes calldata hookData
    ) external payable onlyEntryPointOrSelfOrRoot {
        ValidationStorage storage vs = _validationStorage();
        if (ValidationId.unwrap(_rootValidator) == bytes21(0)) {
            revert InvalidValidator();
        }
        ValidationType vType = ValidatorLib.getType(_rootValidator);
        if (vType != VALIDATION_TYPE_VALIDATOR && vType != VALIDATION_TYPE_PERMISSION) {
            revert InvalidValidationType();
        }
        _setRootValidator(_rootValidator);
        if (_validationStorage().validationConfig[_rootValidator].hook == IHook(HOOK_MODULE_NOT_INSTALLED)) {
            // when new rootValidator is not installed yet
            ValidationConfig memory config = ValidationConfig({nonce: uint32(vs.currentNonce), hook: hook});
            _installValidation(_rootValidator, config, validatorData, hookData);
        }
    }

    function upgradeTo(address _newImplementation) external payable onlyEntryPointOrSelfOrRoot {
        assembly {
            sstore(ERC1967_IMPLEMENTATION_SLOT, _newImplementation)
        }
        emit Upgraded(_newImplementation);
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Kernel";
        version = "0.3.3";
    }

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    fallback() external payable {
        SelectorConfig memory config = _selectorConfig(msg.sig);
        bool success;
        bytes memory result;
        if (address(config.hook) == HOOK_MODULE_NOT_INSTALLED) {
            revert InvalidSelector();
        }
        // action installed
        bytes memory context;
        if (address(config.hook) == HOOK_ONLY_ENTRYPOINT) {
            // for selector manager, address(0) for the hook will default to type(address).max,
            // and this will only allow entrypoints to interact
            if (msg.sender != address(entrypoint)) {
                revert InvalidCaller();
            }
        } else if (address(config.hook) != HOOK_MODULE_INSTALLED) {
            context = _doPreHook(config.hook, msg.value, msg.data);
        }
        // execute action
        if (config.callType == CALLTYPE_SINGLE) {
            (success, result) = ExecLib.doFallback2771Call(config.target);
        } else if (config.callType == CALLTYPE_DELEGATECALL) {
            (success, result) = ExecLib.executeDelegatecall(config.target, msg.data);
        } else {
            revert NotSupportedCallType();
        }
        if (!success) {
            assembly {
                revert(add(result, 0x20), mload(result))
            }
        }
        if (address(config.hook) != HOOK_MODULE_INSTALLED && address(config.hook) != HOOK_ONLY_ENTRYPOINT) {
            _doPostHook(config.hook, context);
        }
        assembly {
            return(add(result, 0x20), mload(result))
        }
    }

    // validation part
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        payable
        override
        onlyEntryPoint
        returns (ValidationData validationData)
    {
        ValidationStorage storage vs = _validationStorage();
        // ONLY ENTRYPOINT
        // Major change for v2 => v3
        // 1. instead of packing 4 bytes prefix to userOp.signature to determine the mode, v3 uses userOp.nonce's first 2 bytes to check the mode
        // 2. instead of packing 20 bytes in userOp.signature for enable mode to provide the validator address, v3 uses userOp.nonce[2:22]
        // 3. In v2, only 1 plugin validator(aside from root validator) can access the selector.
        //    In v3, you can use more than 1 plugin to use the exact selector, you need to specify the validator address in userOp.nonce[2:22] to use the validator
        (ValidationMode vMode, ValidationType vType, ValidationId vId) = ValidatorLib.decodeNonce(userOp.nonce);
        if (vType == VALIDATION_TYPE_ROOT) {
            vId = vs.rootValidator;
        }
        validationData = _validateUserOp(vMode, vId, userOp, userOpHash);
        ValidationConfig memory vc = vs.validationConfig[vId];
        // allow when nonce is not revoked or vType is sudo
        if (vType != VALIDATION_TYPE_ROOT && vc.nonce < vs.validNonceFrom) {
            revert InvalidNonce();
        }
        IHook execHook = vc.hook;
        if (address(execHook) == HOOK_MODULE_NOT_INSTALLED && vType != VALIDATION_TYPE_ROOT) {
            revert InvalidValidator();
        }
        executionHook[userOpHash] = execHook;

        if (address(execHook) == HOOK_MODULE_INSTALLED || address(execHook) == HOOK_MODULE_NOT_INSTALLED) {
            // does not require hook
            if (vType != VALIDATION_TYPE_ROOT && !vs.allowedSelectors[vId][bytes4(userOp.callData[0:4])]) {
                revert InvalidValidator();
            }
        } else {
            // requires hook
            if (vType != VALIDATION_TYPE_ROOT && !vs.allowedSelectors[vId][bytes4(userOp.callData[4:8])]) {
                revert InvalidValidator();
            }
            if (bytes4(userOp.callData[0:4]) != this.executeUserOp.selector) {
                revert OnlyExecuteUserOp();
            }
        }

        assembly {
            if missingAccountFunds {
                pop(call(gas(), caller(), missingAccountFunds, callvalue(), callvalue(), callvalue(), callvalue()))
                //ignore failure (its EntryPoint's job to verify, not account.)
            }
        }
    }

    function isValidSignature(bytes32 hash, bytes calldata data) external view returns (bytes4) {
        return _verifySignature(hash, data);
    }

    // --- Execution ---
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        onlyEntryPoint
    {
        bytes memory context;
        IHook hook = executionHook[userOpHash];
        bool callHook = address(hook) != HOOK_MODULE_INSTALLED;
        if (callHook) {
            // removed 4bytes selector
            context = _doPreHook(hook, msg.value, userOp.callData[4:]);
        }
        (bool success, bytes memory ret) = ExecLib.executeDelegatecall(address(this), userOp.callData[4:]);
        if (!success) {
            revert ExecutionReverted();
        }
        if (callHook) {
            _doPostHook(hook, context);
        }
    }

    function executeFromExecutor(ExecMode execMode, bytes calldata executionCalldata)
        external
        payable
        returns (bytes[] memory returnData)
    {
        // no modifier needed, checking if msg.sender is registered executor will replace the modifier
        IHook hook = _executorConfig(IExecutor(msg.sender)).hook;
        if (address(hook) == HOOK_MODULE_NOT_INSTALLED) {
            revert InvalidExecutor();
        }
        bytes memory context;
        bool callHook = address(hook) != HOOK_MODULE_INSTALLED;
        if (callHook) {
            context = _doPreHook(hook, msg.value, msg.data);
        }
        returnData = ExecLib.execute(execMode, executionCalldata);
        if (callHook) {
            _doPostHook(hook, context);
        }
    }

    function execute(ExecMode execMode, bytes calldata executionCalldata) external payable onlyEntryPointOrSelfOrRoot {
        ExecLib.execute(execMode, executionCalldata);
    }

    function installModule(uint256 moduleType, address module, bytes calldata initData)
        external
        payable
        override
        onlyEntryPointOrSelfOrRoot
    {
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            ValidationStorage storage vs = _validationStorage();
            ValidationId vId = ValidatorLib.validatorToIdentifier(IValidator(module));
            if (vs.validationConfig[vId].nonce == vs.currentNonce) {
                // only increase currentNonce when vId's currentNonce is same
                unchecked {
                    vs.currentNonce++;
                }
            }
            ValidationConfig memory config =
                ValidationConfig({nonce: vs.currentNonce, hook: IHook(address(bytes20(initData[0:20])))});
            InstallValidatorDataFormat calldata data;
            assembly {
                data := add(initData.offset, 20)
            }
            _installValidation(vId, config, data.validatorData, data.hookData);
            if (data.selectorData.length == 4) {
                // NOTE: we don't allow configure on selector data on v3.1+, but using bytes instead of bytes4 for selector data to make sure we are future proof
                _grantAccess(vId, bytes4(data.selectorData[0:4]), true);
            }
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            InstallExecutorDataFormat calldata data;
            assembly {
                data := add(initData.offset, 20)
            }
            IHook hook = IHook(address(bytes20(initData[0:20])));
            _installExecutor(IExecutor(module), data.executorData, hook);
            _installHook(hook, data.hookData);
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            InstallFallbackDataFormat calldata data;
            assembly {
                data := add(initData.offset, 24)
            }
            _installSelector(bytes4(initData[0:4]), module, IHook(address(bytes20(initData[4:24]))), data.selectorData);
            _installHook(IHook(address(bytes20(initData[4:24]))), data.hookData);
        } else if (
            moduleType == MODULE_TYPE_HOOK || moduleType == MODULE_TYPE_POLICY || moduleType == MODULE_TYPE_SIGNER
        ) {
            // force call onInstall for hook, policy, signer
            // NOTE: for hook, kernel does not support independent hook install,
            // NOTE: for policy, kernel does not support independent policy install,
            // NOTE: for signer, kernel does not support independent signer install,
            // hook is expected to be paired with proper validator/executor/selector
            // policy is expected to be paired with proper permissionId
            // to "ADD" permission, use "installValidations()" function
            IHook(module).onInstall(initData);
        } else {
            revert InvalidModuleType();
        }
        emit ModuleInstalled(moduleType, module);
    }

    function grantAccess(ValidationId vId, bytes4 selector, bool allow) external payable onlyEntryPointOrSelfOrRoot {
        _grantAccess(vId, selector, allow);
    }

    function installValidations(
        ValidationId[] calldata vIds,
        ValidationConfig[] memory configs,
        bytes[] calldata validationData,
        bytes[] calldata hookData
    ) external payable onlyEntryPointOrSelfOrRoot {
        _installValidations(vIds, configs, validationData, hookData);
    }

    function uninstallValidation(ValidationId vId, bytes calldata deinitData, bytes calldata hookDeinitData)
        external
        payable
        onlyEntryPointOrSelfOrRoot
    {
        IHook hook = _clearValidationData(vId);
        ValidationType vType = ValidatorLib.getType(vId);
        if (vType == VALIDATION_TYPE_VALIDATOR) {
            IValidator validator = ValidatorLib.getValidator(vId);
            ModuleLib.uninstallModule(address(validator), deinitData);
            emit IERC7579Account.ModuleUninstalled(MODULE_TYPE_VALIDATOR, address(validator));
        } else if (vType == VALIDATION_TYPE_PERMISSION) {
            PermissionId permission = ValidatorLib.getPermissionId(vId);
            _uninstallPermission(permission, deinitData);
        } else {
            revert InvalidValidationType();
        }
        _uninstallHook(hook, hookDeinitData);
    }

    function invalidateNonce(uint32 nonce) external payable onlyEntryPointOrSelfOrRoot {
        _invalidateNonce(nonce);
    }

    function uninstallModule(uint256 moduleType, address module, bytes calldata deInitData)
        external
        payable
        override
        onlyEntryPointOrSelfOrRoot
    {
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            ValidationId vId = ValidatorLib.validatorToIdentifier(IValidator(module));
            _clearValidationData(vId);
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            _clearExecutorData(IExecutor(module));
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            bytes4 selector = bytes4(deInitData[0:4]);
            address target;
            _clearSelectorData(selector);
            if (target == address(0)) {
                return;
            }
            if (target != module) {
                revert InvalidSelector();
            }
            deInitData = deInitData[4:];
        } else if (moduleType == MODULE_TYPE_HOOK) {
            ValidationId vId = _validationStorage().rootValidator;
            if (_validationStorage().validationConfig[vId].hook == IHook(module)) {
                // when root validator hook is being removed
                // remove hook on root validator to prevent kernel from being locked
                _validationStorage().validationConfig[vId].hook = IHook(HOOK_MODULE_INSTALLED);
            }
            // force call onUninstall for hook
            // NOTE: for hook, kernel does not support independent hook install,
            // hook is expected to be paired with proper validator/executor/selector
        } else if (moduleType == MODULE_TYPE_POLICY || moduleType == MODULE_TYPE_SIGNER) {
            ValidationId rootValidator = _validationStorage().rootValidator;
            bytes32 permissionId = bytes32(deInitData[0:32]);
            if (ValidatorLib.getType(rootValidator) == VALIDATION_TYPE_PERMISSION) {
                if (permissionId == bytes32(PermissionId.unwrap(ValidatorLib.getPermissionId(rootValidator)))) {
                    revert RootValidatorCannotBeRemoved();
                }
            }
            // force call onUninstall for policy
            // NOTE: for policy, kernel does not support independent policy install,
            // policy is expected to be paired with proper permissionId
            // to "REMOVE" permission, use "uninstallValidation()" function
            // NOTE: for signer, kernel does not support independent signer install,
            // signer is expected to be paired with proper permissionId
            // to "REMOVE" permission, use "uninstallValidation()" function
        } else {
            revert InvalidModuleType();
        }
        ModuleLib.uninstallModule(module, deInitData);
        emit ModuleUninstalled(moduleType, module);
    }

    function supportsModule(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId < 7;
    }

    function isModuleInstalled(uint256 moduleType, address module, bytes calldata additionalContext)
        external
        view
        override
        returns (bool)
    {
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            return _validationStorage().validationConfig[ValidatorLib.validatorToIdentifier(IValidator(module))].hook
                != IHook(HOOK_MODULE_NOT_INSTALLED);
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            return address(_executorConfig(IExecutor(module)).hook) != HOOK_MODULE_NOT_INSTALLED;
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            return _selectorConfig(bytes4(additionalContext[0:4])).target == module;
        } else {
            return false;
        }
    }

    function accountId() external pure override returns (string memory accountImplementationId) {
        return "kernel.advanced.v0.3.3";
    }

    function supportsExecutionMode(ExecMode mode) external pure override returns (bool) {
        (CallType callType, ExecType execType, ExecModeSelector selector, ExecModePayload payload) =
            ExecLib.decode(mode);
        if (
            callType != CALLTYPE_BATCH && callType != CALLTYPE_SINGLE && callType != CALLTYPE_DELEGATECALL
                && callType != CALLTYPE_STATIC
        ) {
            return false;
        }

        if (
            ExecType.unwrap(execType) != ExecType.unwrap(EXECTYPE_TRY)
                && ExecType.unwrap(execType) != ExecType.unwrap(EXECTYPE_DEFAULT)
        ) {
            return false;
        }

        if (ExecModeSelector.unwrap(selector) != ExecModeSelector.unwrap(EXEC_MODE_DEFAULT)) {
            return false;
        }

        if (ExecModePayload.unwrap(payload) != bytes22(0)) {
            return false;
        }
        return true;
    }
}
