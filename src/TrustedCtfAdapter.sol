// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

/**
 * @title TrustedCtfAdapter
 * @notice Tiny oracle/adapter for Gnosis CTF with AccessControl roles.
 *         - Prepare a condition with this contract as oracle.
 *         - Resolve later (winner index, invalid, or custom vector).
 *         - DEFAULT_ADMIN_ROLE: initialize markets + manage roles
 *         - RESOLVER_ROLE: resolve markets
 *         - BulletinBoard: allows anyone to post updates for questions
 *
 *         conditionId = keccak256(abi.encodePacked(oracle, questionId, outcomeSlotCount))
 *         By preparing with oracle = address(this), only this contract can report payouts.
 */

import { AccessControl } from "lib/openzeppelin-contracts/contracts/access/AccessControl.sol";
import { IConditionalTokens } from "./interfaces/IConditionalTokens.sol";
import { AncillaryDataLib } from "./libraries/AncillaryDataLib.sol";
import { PayoutHelperLib } from "./libraries/PayoutHelperLib.sol";
import { BulletinBoard } from "./mixins/BulletinBoard.sol";

contract TrustedCtfAdapter is AccessControl, BulletinBoard {
    error InvalidAncillaryData();
    error AlreadyInitialized();
    error InvalidPayouts();

    // ---- Roles ----
    bytes32 public constant RESOLVER_ROLE = keccak256("RESOLVER_ROLE");

    // ---- External deps ----
    IConditionalTokens public immutable ctf;

    /// @notice Maximum ancillary data length
    /// From OOV2 function OO_ANCILLARY_DATA_LIMIT
    uint256 public constant MAX_ANCILLARY_DATA = 8139;

    // ---- Market state ----
    struct QuestionData {
        address creator;
        bytes  ancillaryData;
        uint8  slots;     // 2..=256
        bool   prepared;  // prepared on CTF
        bool   resolved;  // payouts reported
    }
    mapping(bytes32 => QuestionData) public questions; // questionId => QuestionData

    // ---- Events ----
    event Initialized(bytes32 indexed questionId, uint8 outcomeSlotCount);
    event Resolved(bytes32 indexed questionId, uint256[] payoutNumerators);

    // ---- Ctor ----
    constructor(address _ctf, address admin) {
        require(_ctf != address(0) && admin != address(0), "zero addr");
        ctf = IConditionalTokens(_ctf);

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(RESOLVER_ROLE, admin); // admin can resolve by default (optional)
    }

    // ---- Admin: create markets ----
    function initialize(bytes memory ancillaryData, uint8 outcomeSlotCount)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    returns (bytes32 questionID) {
        require(outcomeSlotCount >= 2 && outcomeSlotCount <= 255, "bad slots");

        bytes memory data = AncillaryDataLib._appendAncillaryData(msg.sender, ancillaryData);
        if (ancillaryData.length == 0 || data.length > MAX_ANCILLARY_DATA) revert InvalidAncillaryData();

        questionID = keccak256(data);
        if (_isInitialized(questions[questionID])) revert AlreadyInitialized();
        
        _saveQuestionData(questionID, msg.sender, ancillaryData, outcomeSlotCount);

        ctf.prepareCondition(address(this), questionID, outcomeSlotCount);
        emit Initialized(questionID, outcomeSlotCount);
    }

    // ---- Resolve helpers ----

    /// @notice Resolve with a winner index (one-hot).
    function resolveWithIndex(bytes32 questionId, uint256 winningIdx)
        external
        onlyRole(RESOLVER_ROLE)
    {
        QuestionData storage m = _needPreparedNotResolved(questionId);
        require(winningIdx < m.slots, "bad index");

        uint256[] memory p = new uint256[](m.slots);
        p[winningIdx] = 1;

        m.resolved = true;
        ctf.reportPayouts(questionId, p);
        emit Resolved(questionId, p);
    }

    /// @notice Resolve as invalid: all outcomes redeem equally.
    function resolveInvalid(bytes32 questionId)
        external
        onlyRole(RESOLVER_ROLE)
    {
        QuestionData storage m = _needPreparedNotResolved(questionId);

        uint256[] memory p = new uint256[](m.slots);
        for (uint256 i = 0; i < m.slots; i++) p[i] = 1;

        m.resolved = true;
        ctf.reportPayouts(questionId, p);
        emit Resolved(questionId, p);
    }

    /// @notice Resolve with a custom payout vector (length==slots, sum>0).
    function resolveWithVector(bytes32 questionId, uint256[] calldata payoutNumerators)
        external
        onlyRole(RESOLVER_ROLE)
    {
        QuestionData storage m = _needPreparedNotResolved(questionId);
        if (!_isValidPayoutArray(payoutNumerators)) revert InvalidPayouts();
        _checkPayouts(payoutNumerators, m.slots);

        m.resolved = true;
        ctf.reportPayouts(questionId, payoutNumerators);
        emit Resolved(questionId, payoutNumerators);
    }

    // ---- Internals ----
    function _needPreparedNotResolved(bytes32 questionId)
        internal
        view
        returns (QuestionData storage m)
    {
        m = questions[questionId];
        require(m.prepared, "not prepared");
        require(!m.resolved, "resolved");
    }

    function _checkPayouts(uint256[] calldata v, uint8 slots) internal pure {
        require(v.length == slots, "bad payouts");
        uint256 sum;
        for (uint256 i = 0; i < v.length; i++) sum += v[i];
        require(sum > 0, "zero sum");
    }

    function _isInitialized(QuestionData storage questionData) internal view returns (bool) {
        return questionData.ancillaryData.length > 0;
    }

    /// @notice Validates a payout array from the admin
    /// @param payouts - The payout array
    function _isValidPayoutArray(uint256[] calldata payouts) internal pure returns (bool) {
        return PayoutHelperLib.isValidPayoutArray(payouts);
    }

    function _saveQuestionData(bytes32 questionID, address creator, bytes memory ancillaryData, uint8 outcomeSlotCount) internal {
        questions[questionID] = QuestionData(creator, ancillaryData, outcomeSlotCount, true, false);
    }
}
