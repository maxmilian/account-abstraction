// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import "../core/BaseAccount.sol";
import "./callback/TokenCallbackHandler.sol";

/**
  * minimal account.
  *  this is sample minimal account.
  *  has execute, eth handling methods
  *  has a single signer that can send requests through the entryPoint.
  */
contract SimpleAccount is BaseAccount, TokenCallbackHandler, UUPSUpgradeable, Initializable {
    using ECDSA for bytes32;

    address public owner;

    IEntryPoint private immutable _entryPoint;

    event SimpleAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }


    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    function _onlyOwner() internal view {
        //directly from EOA owner, or through the account itself (which gets redirected through execute())
        require(msg.sender == owner || msg.sender == address(this), "only owner");
    }

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _requireFromEntryPointOrOwner();
        _call(dest, value, func);
    }

    /**
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, bytes[] calldata func) external {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of SimpleAccount must be deployed with the new EntryPoint address, then upgrading
      * the implementation by calling `upgradeTo()`
     */
    function initialize(address anOwner) public virtual initializer {
        _initialize(anOwner);
    }

    function _initialize(address anOwner) internal virtual {
        owner = anOwner;
        emit SimpleAccountInitialized(_entryPoint, owner);
    }

    // Require the function call went through EntryPoint or owner
    function _requireFromEntryPointOrOwner() internal view {
        require(msg.sender == address(entryPoint()) || msg.sender == owner, "account: not Owner or EntryPoint");
    }

    /// implement template method of BaseAccount
    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash)
    internal override virtual returns (uint256 validationData) {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        if (owner != hash.recover(userOp.signature))
            return SIG_VALIDATION_FAILED;
        return 0;
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value : value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value : msg.value}(address(this));
    }

    /**
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyOwner {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation);
        _onlyOwner();
    }

    // expire after voting: 30m
    uint256 private constant RECOVERY_EXPIRE = 1800;
    // Current owner can revoke the voting decision when new owner don't take ownership from old owner
    // New owner cannot take ownership during ONBOARD_PERIOD
    uint256 private constant ONBOARD_PERIOD = 1800;

    uint private recoveryOnboardAfter = 0;
    address public recoveryOnboardOwner = address(0);

    address[] private guardians;
    // 記錄Guardian投票的時間
    mapping(address => uint256) private votingTimes;
    // 要恢復的新公鑰位置
    mapping(address => address) private recoveryAddress;

    event NewOwnerProposed(address indexed newOwner);
    event NewOwnerOnboard(address indexed owner, uint time);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier guardianSize() {
        _checkGuardSize();
        _;
    }

    function _checkGuardSize() internal view virtual {
        require(guardians.length >= 3 && guardians.length <= 9, "Invalid size of guardians");
    }

    function proposalThreshold() public view guardianSize returns (uint256) {
        return (guardians.length + 3) / 4;
    }

    function votingThreshold() public view guardianSize returns (uint256) {
        return (guardians.length * 2) / 3;
    }

    function getGuardians() public view returns (address[] memory) {
        return guardians;
    }

    function addGuardian(address addr) public onlyOwner {
        require(_isGuardian(addr) == false, "address is already be one of guardians.");
        require(guardians.length <= 8, "Invalid number of guardians");
        votingTimes[addr] = 1;
        guardians.push(addr);
    }

    function revokeGuardian(address addr) public onlyOwner {
        require(_isGuardian(addr) == true, "address must be one of guardians.");

        bool found = false;
        for (uint i = 0; i < guardians.length-1; i++) {
            if (found) {
                guardians[i] = guardians[i + 1];
            } else if (guardians[i] == addr) {
                found = true;
                guardians[i] = guardians[i + 1];
            }
        }
        guardians.pop();
        delete votingTimes[addr];
    }

    function setGuardians(address[] memory _newGuardians) public onlyOwner {
        require(_newGuardians.length >= 3 && _newGuardians.length <= 9, "Invalid number of guardians");
        for (uint i = 0; i < guardians.length; i++) {
            delete votingTimes[guardians[i]];
        }
        guardians = _newGuardians;
        for (uint i = 0; i < guardians.length; i++) {
            votingTimes[guardians[i]] = 1;
        }
    }

    function _isGuardian(address account) internal view returns (bool) {
        return votingTimes[account] > 0;
    }

    function _getAcceptableRecoveryAddress(uint threshold) internal view returns (address) {
        require(threshold >= 1, "The minimun of thresold is 1.");
        require(threshold <= 9, "The maximum of thresold is 9.");

        uint256 maxCount = 0;
        address maxRecoveryAddress;

        for (uint256 i = 0; i < guardians.length; i++) {
            address recovery = recoveryAddress[guardians[i]];
            if (recovery != address(0)) {
                uint256 count = 0;
                for (uint256 j = 0; j < guardians.length; j++) {
                    if (recoveryAddress[guardians[j]] == recovery) {
                        count++;
                    }
                }
                if (count > maxCount) {
                    maxCount = count;
                    maxRecoveryAddress = recovery;
                }
            }
        }

        if (maxCount < threshold) {
            return address(0);
        }

        return maxRecoveryAddress;
    }

    function doVoteProposal(address newAccount) public guardianSize {
        require(_isGuardian(msg.sender) == true, "You must be one of guardians.");
        require(newAccount != address(0), "Invalid new account address.");

        votingTimes[msg.sender] = block.timestamp;
        recoveryAddress[msg.sender] = newAccount;

        uint count = 0;
        for (uint i = 0; i < guardians.length; i++) {
            if (_votingExpired(guardians[i])) {
                votingTimes[guardians[i]] = 1;
                recoveryAddress[guardians[i]] = address(0);
            } else {
                count += 1;
            }
        }

        if (count > 0) {
            uint threshold = proposalThreshold();
            if (count == threshold) {
                address newProposedOwner = _getAcceptableRecoveryAddress(threshold);
                emit NewOwnerProposed(newProposedOwner);
            } else if (count > threshold) {
                threshold = votingThreshold();
                address newOwner = _getAcceptableRecoveryAddress(threshold);
                if (newOwner != address(0)) {
                    recoveryOnboardOwner = newOwner;
                    recoveryOnboardAfter = block.timestamp + ONBOARD_PERIOD;
                    emit NewOwnerOnboard(newOwner, recoveryOnboardAfter);
                }
            }
        }

    }

    function _votingExpired(address _guardian) internal view returns (bool) {
        return _isGuardian(_guardian) && (block.timestamp - votingTimes[_guardian] > RECOVERY_EXPIRE);
    }

    function revokeVoting() public onlyOwner {
        recoveryOnboardOwner = address(0);
        recoveryOnboardAfter = 0;
    }

    function takeOwnershipt() public {
        require(recoveryOnboardOwner != address(0), "no new owner");
        require(msg.sender == recoveryOnboardOwner, "only new owner can take ownershipt");
        require(block.timestamp > recoveryOnboardAfter , "new owner should take ownership after recoveryOnboardAfter");

        address oldOwner = owner;
        owner = recoveryOnboardOwner;
        emit OwnershipTransferred(oldOwner, owner);
    }
}