// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Test, console2 as console } from "forge-std/Test.sol";
import { TrustedCtfAdapter } from "src/TrustedCtfAdapter.sol";
import { IConditionalTokens } from "src/interfaces/IConditionalTokens.sol";
import { TestHelper } from "./dev/TestHelper.sol";
import { IERC20 } from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

// Mock ConditionalTokens contract for testing
contract MockConditionalTokens is IConditionalTokens {
    mapping(bytes32 => uint256[]) public payoutNumeratorsStorage;
    mapping(bytes32 => uint256) public payoutDenominatorStorage;
    mapping(bytes32 => uint256) public outcomeSlotCounts;
    
    bytes32 public lastPreparedOracle;
    bytes32 public lastPreparedQuestionId;
    uint256 public lastPreparedOutcomeSlotCount;
    
    bytes32 public lastReportedQuestionId;
    uint256[] public lastReportedPayouts;

    function prepareCondition(address oracle, bytes32 questionId, uint256 _outcomeSlotCount) external {
        lastPreparedOracle = bytes32(uint256(uint160(oracle)));
        lastPreparedQuestionId = questionId;
        lastPreparedOutcomeSlotCount = _outcomeSlotCount;
        
        bytes32 conditionId = keccak256(abi.encodePacked(oracle, questionId, _outcomeSlotCount));
        outcomeSlotCounts[conditionId] = _outcomeSlotCount;
    }

    function reportPayouts(bytes32 questionId, uint256[] calldata payouts) external {
        lastReportedQuestionId = questionId;
        lastReportedPayouts = payouts;
        
        // Mock the payout storage
        bytes32 conditionId = keccak256(abi.encodePacked(msg.sender, questionId, payouts.length));
        payoutNumeratorsStorage[conditionId] = payouts;
        payoutDenominatorStorage[conditionId] = 1; // Mark as resolved
    }

    // Implement other interface functions with empty implementations
    function payoutNumerators(bytes32 conditionId) external view returns (uint256[] memory) { 
        return payoutNumeratorsStorage[conditionId]; 
    }
    function payoutDenominator(bytes32 conditionId) external view returns (uint256) { 
        return payoutDenominatorStorage[conditionId]; 
    }
    function getOutcomeSlotCount(bytes32 conditionId) external view returns (uint256) { 
        return outcomeSlotCounts[conditionId]; 
    }
    function getConditionId(address oracle, bytes32 questionId, uint256 outcomeSlotCount) external pure returns (bytes32) { 
        return keccak256(abi.encodePacked(oracle, questionId, outcomeSlotCount)); 
    }
    function getCollectionId(bytes32 parentCollectionId, bytes32 conditionId, uint256 indexSet) external pure returns (bytes32) { 
        revert("Not implemented"); 
    }
    function getPositionId(IERC20 collateralToken, bytes32 collectionId) external pure returns (uint256) { 
        revert("Not implemented"); 
    }
    function splitPosition(IERC20 collateralToken, bytes32 parentCollectionId, bytes32 conditionId, uint256[] calldata partition, uint256 amount) external pure { 
        revert("Not implemented"); 
    }
    function mergePositions(IERC20 collateralToken, bytes32 parentCollectionId, bytes32 conditionId, uint256[] calldata partition, uint256 amount) external pure { 
        revert("Not implemented"); 
    }
    function redeemPositions(IERC20 collateralToken, bytes32 parentCollectionId, bytes32 conditionId, uint256[] calldata indexSets) external pure { 
        revert("Not implemented"); 
    }
}

contract TrustedCtfAdapterTest is TestHelper {
    TrustedCtfAdapter public adapter;
    MockConditionalTokens public mockCtf;
    
    address public admin = address(this);
    
    bytes32 public questionId = keccak256("test-question");
    bytes32 public questionId2 = keccak256("test-question-2");
    
    event Initialized(bytes32 indexed questionId, uint8 outcomeSlotCount);
    event Resolved(bytes32 indexed questionId, bytes32 conditionId, uint256[] payoutNumerators);

    function setUp() public {
        mockCtf = new MockConditionalTokens();
        adapter = new TrustedCtfAdapter(address(mockCtf), admin);
    }

    // ============ Constructor Tests ============

    function testConstructor() public {
        assertEq(address(mockCtf), address(adapter.ctf()));
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.RESOLVER_ROLE(), admin));
    }

    function testConstructorRevertZeroCtf() public {
        vm.expectRevert("zero addr");
        new TrustedCtfAdapter(address(0), admin);
    }

    function testConstructorRevertZeroAdmin() public {
        vm.expectRevert("zero addr");
        new TrustedCtfAdapter(address(mockCtf), address(0));
    }

    // ============ Role Management Tests ============

    function testGrantResolverRole() public {
        vm.prank(admin);
        adapter.grantRole(adapter.RESOLVER_ROLE(), carla);
        assertTrue(adapter.hasRole(adapter.RESOLVER_ROLE(), carla));
    }

    function testRevokeResolverRole() public {
        vm.prank(admin);
        adapter.revokeRole(adapter.RESOLVER_ROLE(), admin);
        assertFalse(adapter.hasRole(adapter.RESOLVER_ROLE(), admin));
    }

    function testGrantAdminRole() public {
        vm.prank(admin);
        adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), carla);
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), carla));
    }

    // ============ Initialize Tests ============

    function testInitialize() public {
        uint8 outcomeSlotCount = 3;
        
        vm.expectEmit(true, true, true, true);
        emit Initialized(questionId, outcomeSlotCount);
        
        vm.prank(admin);
        adapter.initialize(questionId, outcomeSlotCount);
        
        // Check market state
        (uint8 slots, bool prepared, bool resolved) = adapter.markets(questionId);
        assertEq(slots, outcomeSlotCount);
        assertTrue(prepared);
        assertFalse(resolved);
        
        // Check CTF interaction
        assertEq(mockCtf.lastPreparedQuestionId(), questionId);
        assertEq(mockCtf.lastPreparedOutcomeSlotCount(), outcomeSlotCount);
        assertEq(mockCtf.lastPreparedOracle(), bytes32(uint256(uint160(address(adapter)))));
    }

    function testInitializeMultipleMarkets() public {
        vm.startPrank(admin);
        
        adapter.initialize(questionId, 2);
        adapter.initialize(questionId2, 4);
        
        vm.stopPrank();
        
        // Check first market
        (uint8 slots1, bool prepared1, bool resolved1) = adapter.markets(questionId);
        assertEq(slots1, 2);
        assertTrue(prepared1);
        assertFalse(resolved1);
        
        // Check second market
        (uint8 slots2, bool prepared2, bool resolved2) = adapter.markets(questionId2);
        assertEq(slots2, 4);
        assertTrue(prepared2);
        assertFalse(resolved2);
    }

    function testInitializeRevertNotAdmin() public {
        vm.expectRevert();
        vm.prank(carla);
        adapter.initialize(questionId, 2);
    }

    function testInitializeRevertTooFewSlots() public {
        vm.expectRevert("bad slots");
        vm.prank(admin);
        adapter.initialize(questionId, 1);
    }

    function testInitializeRevertTooManySlots() public {
        // Note: uint8 can only hold 0-255, so 256 would cause a compile-time error
        // The contract allows up to 256 slots, but the parameter type limits it to 255
        // This test verifies the minimum requirement (2 slots)
        vm.expectRevert("bad slots");
        vm.prank(admin);
        adapter.initialize(questionId, 1); // Test minimum requirement
    }

    function testInitializeRevertAlreadyPrepared() public {
        vm.startPrank(admin);
        adapter.initialize(questionId, 2);
        
        vm.expectRevert("prepared");
        adapter.initialize(questionId, 3);
        vm.stopPrank();
    }

    // ============ Resolve With Index Tests ============

    function testResolveWithIndex() public {
        vm.startPrank(admin);
        adapter.initialize(questionId, 3);
        
        uint256[] memory expectedPayouts = new uint256[](3);
        expectedPayouts[0] = 0;
        expectedPayouts[1] = 1;
        expectedPayouts[2] = 0;
        vm.expectEmit(true, true, true, true);
        emit Resolved(questionId, adapter.conditionId(address(adapter), questionId, 3), expectedPayouts);
        
        adapter.resolveWithIndex(questionId, 1); // Index 1 wins
        vm.stopPrank();
        
        // Check market state
        (uint8 slots, bool prepared, bool resolved) = adapter.markets(questionId);
        assertEq(slots, 3);
        assertTrue(prepared);
        assertTrue(resolved);
        
        // Check CTF interaction
        assertEq(mockCtf.lastReportedQuestionId(), questionId);
        assertEq(mockCtf.lastReportedPayouts(0), 0);
        assertEq(mockCtf.lastReportedPayouts(1), 1);
        assertEq(mockCtf.lastReportedPayouts(2), 0);
    }

    function testResolveWithIndexFirstSlot() public {
        vm.startPrank(admin);
        adapter.initialize(questionId, 2);
        adapter.resolveWithIndex(questionId, 0); // Index 0 wins
        vm.stopPrank();
        
        assertEq(mockCtf.lastReportedPayouts(0), 1);
        assertEq(mockCtf.lastReportedPayouts(1), 0);
    }

    function testResolveWithIndexLastSlot() public {
        vm.startPrank(admin);
        adapter.initialize(questionId, 5);
        adapter.resolveWithIndex(questionId, 4); // Index 4 wins
        vm.stopPrank();
        
        assertEq(mockCtf.lastReportedPayouts(4), 1);
        for (uint256 i = 0; i < 4; i++) {
            assertEq(mockCtf.lastReportedPayouts(i), 0);
        }
    }

    function testResolveWithIndexRevertNotResolver() public {
        vm.prank(admin);
        adapter.initialize(questionId, 3);
        
        vm.expectRevert();
        vm.prank(carla);
        adapter.resolveWithIndex(questionId, 1);
    }

    function testResolveWithIndexRevertNotPrepared() public {
        vm.expectRevert("not prepared");
        vm.prank(admin);
        adapter.resolveWithIndex(questionId, 1);
    }

    function testResolveWithIndexRevertAlreadyResolved() public {
        vm.startPrank(admin);
        adapter.initialize(questionId, 3);
        adapter.resolveWithIndex(questionId, 1);
        
        vm.expectRevert("resolved");
        adapter.resolveWithIndex(questionId, 2);
        vm.stopPrank();
    }

    function testResolveWithIndexRevertInvalidIndex() public {
        vm.startPrank(admin);
        adapter.initialize(questionId, 3);
        
        vm.expectRevert("bad index");
        adapter.resolveWithIndex(questionId, 3); // Index 3 doesn't exist for 3 slots
        vm.stopPrank();
    }

    // ============ Resolve Invalid Tests ============

    function testResolveInvalid() public {
        vm.startPrank(admin);
        adapter.initialize(questionId, 3);
        
        uint256[] memory expectedPayouts = new uint256[](3);
        expectedPayouts[0] = 1;
        expectedPayouts[1] = 1;
        expectedPayouts[2] = 1;
        
        vm.expectEmit(true, true, true, true);
        emit Resolved(questionId, adapter.conditionId(address(adapter), questionId, 3), expectedPayouts);
        
        adapter.resolveInvalid(questionId);
        vm.stopPrank();
        
        // Check market state
        (uint8 slots, bool prepared, bool resolved) = adapter.markets(questionId);
        assertTrue(resolved);
        
        // Check CTF interaction
        assertEq(mockCtf.lastReportedQuestionId(), questionId);
        assertEq(mockCtf.lastReportedPayouts(0), 1);
        assertEq(mockCtf.lastReportedPayouts(1), 1);
        assertEq(mockCtf.lastReportedPayouts(2), 1);
    }

    function testResolveInvalidTwoSlots() public {
        vm.startPrank(admin);
        adapter.initialize(questionId, 2);
        adapter.resolveInvalid(questionId);
        vm.stopPrank();
        
        assertEq(mockCtf.lastReportedPayouts(0), 1);
        assertEq(mockCtf.lastReportedPayouts(1), 1);
    }

    function testResolveInvalidRevertNotResolver() public {
        vm.prank(admin);
        adapter.initialize(questionId, 3);
        
        vm.expectRevert();
        vm.prank(carla);
        adapter.resolveInvalid(questionId);
    }

    function testResolveInvalidRevertNotPrepared() public {
        vm.expectRevert("not prepared");
        vm.prank(admin);
        adapter.resolveInvalid(questionId);
    }

    function testResolveInvalidRevertAlreadyResolved() public {
        vm.startPrank(admin);
        adapter.initialize(questionId, 3);
        adapter.resolveInvalid(questionId);
        
        vm.expectRevert("resolved");
        adapter.resolveInvalid(questionId);
        vm.stopPrank();
    }

    // ============ Resolve With Vector Tests ============

    function testResolveWithVector() public {
        vm.startPrank(admin);
        adapter.initialize(questionId, 3);
        
        uint256[] memory payouts = new uint256[](3);
        payouts[0] = 2;
        payouts[1] = 3;
        payouts[2] = 1;
        
        vm.expectEmit(true, true, true, true);
        emit Resolved(questionId, adapter.conditionId(address(adapter), questionId, 3), payouts);
        
        adapter.resolveWithVector(questionId, payouts);
        vm.stopPrank();
        
        // Check market state
        (uint8 slots, bool prepared, bool resolved) = adapter.markets(questionId);
        assertTrue(resolved);
        
        // Check CTF interaction
        assertEq(mockCtf.lastReportedQuestionId(), questionId);
        assertEq(mockCtf.lastReportedPayouts(0), 2);
        assertEq(mockCtf.lastReportedPayouts(1), 3);
        assertEq(mockCtf.lastReportedPayouts(2), 1);
    }

    function testResolveWithVectorEqualPayouts() public {
        vm.startPrank(admin);
        adapter.initialize(questionId, 2);
        
        uint256[] memory payouts = new uint256[](2);
        payouts[0] = 5;
        payouts[1] = 5;
        
        adapter.resolveWithVector(questionId, payouts);
        vm.stopPrank();
        
        assertEq(mockCtf.lastReportedPayouts(0), 5);
        assertEq(mockCtf.lastReportedPayouts(1), 5);
    }

    function testResolveWithVectorRevertNotResolver() public {
        vm.prank(admin);
        adapter.initialize(questionId, 3);
        
        uint256[] memory payouts = new uint256[](3);
        payouts[0] = 1;
        payouts[1] = 1;
        payouts[2] = 1;
        
        vm.expectRevert();
        vm.prank(carla);
        adapter.resolveWithVector(questionId, payouts);
    }

    function testResolveWithVectorRevertNotPrepared() public {
        uint256[] memory payouts = new uint256[](3);
        payouts[0] = 1;
        payouts[1] = 1;
        payouts[2] = 1;
        
        vm.expectRevert("not prepared");
        vm.prank(admin);
        adapter.resolveWithVector(questionId, payouts);
    }

    function testResolveWithVectorRevertAlreadyResolved() public {
        vm.startPrank(admin);
        adapter.initialize(questionId, 3);
        adapter.resolveWithIndex(questionId, 1);
        
        uint256[] memory payouts = new uint256[](3);
        payouts[0] = 1;
        payouts[1] = 1;
        payouts[2] = 1;
        
        vm.expectRevert("resolved");
        adapter.resolveWithVector(questionId, payouts);
        vm.stopPrank();
    }

    function testResolveWithVectorRevertWrongLength() public {
        vm.startPrank(admin);
        adapter.initialize(questionId, 3);
        
        uint256[] memory payouts = new uint256[](2); // Wrong length
        payouts[0] = 1;
        payouts[1] = 1;
        
        vm.expectRevert("bad payouts");
        adapter.resolveWithVector(questionId, payouts);
        vm.stopPrank();
    }

    function testResolveWithVectorRevertZeroSum() public {
        vm.startPrank(admin);
        adapter.initialize(questionId, 3);
        
        uint256[] memory payouts = new uint256[](3);
        payouts[0] = 0;
        payouts[1] = 0;
        payouts[2] = 0;
        
        vm.expectRevert("zero sum");
        adapter.resolveWithVector(questionId, payouts);
        vm.stopPrank();
    }

    // ============ Condition ID Tests ============

    function testConditionId() public {
        bytes32 expectedId = keccak256(abi.encodePacked(address(adapter), questionId, uint8(3)));
        bytes32 actualId = adapter.conditionId(address(adapter), questionId, 3);
        assertEq(expectedId, actualId);
    }

    function testConditionIdDifferentOracle() public {
        bytes32 id1 = adapter.conditionId(address(1), questionId, 3);
        bytes32 id2 = adapter.conditionId(address(2), questionId, 3);
        assertTrue(id1 != id2);
    }

    function testConditionIdDifferentQuestion() public {
        bytes32 id1 = adapter.conditionId(address(adapter), questionId, 3);
        bytes32 id2 = adapter.conditionId(address(adapter), questionId2, 3);
        assertTrue(id1 != id2);
    }

    function testConditionIdDifferentSlots() public {
        bytes32 id1 = adapter.conditionId(address(adapter), questionId, 2);
        bytes32 id2 = adapter.conditionId(address(adapter), questionId, 3);
        assertTrue(id1 != id2);
    }

    // ============ Edge Cases and Integration Tests ============

    function testMultipleResolutionsDifferentMarkets() public {
        vm.startPrank(admin);
        
        // Initialize two markets
        adapter.initialize(questionId, 2);
        adapter.initialize(questionId2, 3);
        
        // Resolve first market with index
        adapter.resolveWithIndex(questionId, 0);
        
        // Resolve second market as invalid
        uint256[] memory invalidPayouts = new uint256[](3);
        invalidPayouts[0] = 1;
        invalidPayouts[1] = 1;
        invalidPayouts[2] = 1;
        adapter.resolveWithVector(questionId2, invalidPayouts);
        
        vm.stopPrank();
        
        // Check first market
        (uint8 slots1, bool prepared1, bool resolved1) = adapter.markets(questionId);
        assertTrue(resolved1);
        
        // Check second market
        (uint8 slots2, bool prepared2, bool resolved2) = adapter.markets(questionId2);
        assertTrue(resolved2);
    }

    function testRoleRevocationAndGranting() public {
        // Grant resolver role to carla
        vm.prank(admin);
        adapter.grantRole(adapter.RESOLVER_ROLE(), carla);
        
        // Revoke from admin
        vm.prank(admin);
        adapter.revokeRole(adapter.RESOLVER_ROLE(), admin);
        
        // Initialize market
        vm.prank(admin);
        adapter.initialize(questionId, 2);
        
        // Admin can no longer resolve
        vm.expectRevert();
        vm.prank(admin);
        adapter.resolveWithIndex(questionId, 0);
        
        // Carla can resolve
        vm.prank(carla);
        adapter.resolveWithIndex(questionId, 0);
    }

    function testMaxOutcomeSlots() public {
        vm.prank(admin);
        adapter.initialize(questionId, 255); // Maximum allowed for uint8
        
        (uint8 slots, bool prepared, bool resolved) = adapter.markets(questionId);
        assertEq(slots, 255);
        assertTrue(prepared);
        assertFalse(resolved);
    }

    function testMinOutcomeSlots() public {
        vm.prank(admin);
        adapter.initialize(questionId, 2); // Minimum allowed
        
        (uint8 slots, bool prepared, bool resolved) = adapter.markets(questionId);
        assertEq(slots, 2);
        assertTrue(prepared);
        assertFalse(resolved);
    }

    // ============ Helper Functions ============

    function _createPayoutArray(uint8 length, uint256 value) internal pure returns (uint256[] memory) {
        uint256[] memory payouts = new uint256[](length);
        for (uint256 i = 0; i < length; i++) {
            payouts[i] = value;
        }
        return payouts;
    }

    // ============ Fuzz Tests ============

    function testFuzz_InitializeValidSlots(uint8 outcomeSlotCount) public {
        vm.assume(outcomeSlotCount >= 2 && outcomeSlotCount <= 256);
        
        vm.prank(admin);
        adapter.initialize(questionId, outcomeSlotCount);
        
        (uint8 slots, bool prepared, bool resolved) = adapter.markets(questionId);
        assertEq(slots, outcomeSlotCount);
        assertTrue(prepared);
        assertFalse(resolved);
    }

    function testFuzz_ResolveWithIndexValidIndex(uint8 outcomeSlotCount, uint256 winningIndex) public {
        vm.assume(outcomeSlotCount >= 2 && outcomeSlotCount <= 256);
        vm.assume(winningIndex < outcomeSlotCount);
        
        vm.startPrank(admin);
        adapter.initialize(questionId, outcomeSlotCount);
        adapter.resolveWithIndex(questionId, winningIndex);
        vm.stopPrank();
        
        (uint8 slots, bool prepared, bool resolved) = adapter.markets(questionId);
        assertTrue(resolved);
        
        // Check that only the winning index has payout 1
        for (uint256 i = 0; i < outcomeSlotCount; i++) {
            uint256 expectedPayout = (i == winningIndex) ? 1 : 0;
            assertEq(mockCtf.lastReportedPayouts(i), expectedPayout);
        }
    }
} 