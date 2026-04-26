// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {InstitutionalVault} from "../../src/edu/InstitutionalVault.sol";
import {ClassroomClusterV1} from "../../src/edu/ClassroomClusterV1.sol";
import {Forwarder} from "../../src/edu/Forwarder.sol";
import {BudgetAllocation} from "../../src/edu/BudgetAllocation.sol";
import {CashoutRequest} from "../../src/edu/CashoutRequest.sol";
import {IClassroomCluster} from "../../src/edu/interfaces/IClassroomCluster.sol";
import {IForwarder} from "../../src/edu/interfaces/IForwarder.sol";
import {ICashoutRequest} from "../../src/edu/interfaces/ICashoutRequest.sol";

/// @notice Simple training data recorder for integration tests
contract TrainingDataRecorder {
    struct Tuple {
        bytes32 orgPrincipalId;
        uint256 classroomId;
        bytes32 commitmentHash;
    }

    Tuple[] public tuples;

    function submitTrainingData(bytes32 orgPrincipalId, uint256 classroomId, bytes32 commitmentHash) external {
        tuples.push(Tuple(orgPrincipalId, classroomId, commitmentHash));
    }

    function getTupleCount() external view returns (uint256) {
        return tuples.length;
    }
}

/// @title EduStackIntegrationTest
/// @notice Full end-to-end test of the institutional education smart contract stack.
///         Simulates: school setup → classroom creation → device provisioning →
///         student enrollment → budget allocation → student contribution via forwarder →
///         teacher cashout request → admin approval.
contract EduStackIntegrationTest is Test {
    InstitutionalVault vault;
    ClassroomClusterV1 cluster;
    Forwarder forwarder;
    BudgetAllocation budget;
    CashoutRequest cashout;
    TrainingDataRecorder recorder;

    // Actors
    address principal = address(0x1001);  // School principal (signer)
    address vp = address(0x1002);         // Vice principal (signer)
    address cfo = address(0x1003);        // CFO (signer)
    address itDir = address(0x2001);      // IT director
    address relayer = address(0x3001);    // Institutional relayer
    address teacher1 = address(0x4001);   // Biology teacher
    uint256 student1Key = 0x5001;
    uint256 student2Key = 0x5002;
    uint256 student3Key = 0x5003;
    address student1;                     // Student

    bytes32 device1Cert = keccak256("chromebook-bio-001");
    bytes32 studentPrincipal = keccak256("hmac-student-001");

    function setUp() public {
        student1 = vm.addr(student1Key);

        // 1. Deploy vault with 3-of-3 multi-sig (principal, VP, CFO)
        address[] memory signers = new address[](3);
        signers[0] = principal;
        signers[1] = vp;
        signers[2] = cfo;
        vault = new InstitutionalVault(signers, 2); // 2-of-3
        vm.deal(address(vault), 1000 ether); // Fund vault with 1000 SALT

        // 2. Deploy cluster with vault as governance
        cluster = new ClassroomClusterV1(address(vault));

        // 3. Deploy forwarder
        forwarder = new Forwarder(address(vault), address(cluster), address(vault));

        // 4. Deploy budget and cashout
        budget = new BudgetAllocation(address(vault));
        cashout = new CashoutRequest(address(vault), 100); // $0.01/SALT

        // 5. Deploy training data recorder (target for student meta-tx)
        recorder = new TrainingDataRecorder();

        // 6. Setup org roles (governance = vault, so we prank as vault)
        // In production, these would be multi-sig transactions through the vault
        vm.startPrank(address(vault));
        cluster.grantOrgRole(principal, IClassroomCluster.OrgRole.Admin);
        cluster.grantOrgRole(itDir, IClassroomCluster.OrgRole.IT);
        forwarder.addRelayer(relayer);
        forwarder.setTargetAllowed(address(recorder), true);
        vm.stopPrank();
    }

    function _signForwardRequest(
        IForwarder.ForwardRequest memory req,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 digest = forwarder.hashForwardRequest(req);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _executeAsRelayer(
        IForwarder.ForwardRequest memory req,
        bytes memory signature
    ) internal returns (bool) {
        vm.prank(relayer);
        return forwarder.execute(req, signature);
    }

    // ===================================================================
    // E2E SCENARIO 1: Full School Setup → Student Contribution → Cashout
    // ===================================================================

    function test_e2e_full_school_workflow() public {
        // Step 1: Admin creates a classroom
        vm.prank(principal);
        uint256 classroomId = cluster.createClassroom("Biology 101", teacher1, 10, 2026, "A");
        assertEq(cluster.getClassroomName(classroomId), "Biology 101");
        assertEq(cluster.getClassroomTeacher(classroomId), teacher1);

        // Step 2: IT provisions a device
        vm.prank(itDir);
        cluster.registerDevice(device1Cert, student1);
        assertTrue(cluster.isDeviceActive(device1Cert));

        // Step 3: Teacher adds student to classroom
        vm.prank(teacher1);
        cluster.grantClassroomRole(classroomId, student1, IClassroomCluster.ClassroomRole.Student);
        assertEq(uint256(cluster.getClassroomRole(classroomId, student1)),
                 uint256(IClassroomCluster.ClassroomRole.Student));
        assertEq(cluster.getStudentCount(classroomId), 1);

        // Step 4: Admin allocates budget for classroom
        vm.prank(address(vault));
        budget.allocateBudget(classroomId, 100 ether, 50 ether);
        assertEq(budget.getRemaining(classroomId), 100 ether);

        // Step 5: Student submits training data via forwarder
        bytes memory trainingCall = abi.encodeWithSelector(
            TrainingDataRecorder.submitTrainingData.selector,
            studentPrincipal,
            classroomId,
            keccak256("photosynthesis-correction-001")
        );

        IForwarder.ForwardRequest memory req = IForwarder.ForwardRequest({
            orgPrincipalId: studentPrincipal,
            classroomId: classroomId,
            nonce: 0,
            sessionExpiry: block.timestamp + 2700, // 45 min
            deviceCertHash: device1Cert,
            target: address(recorder),
            data: trainingCall
        });

        bool success = _executeAsRelayer(req, _signForwardRequest(req, student1Key));
        assertTrue(success);
        assertEq(recorder.getTupleCount(), 1);

        // Step 6: Teacher requests cashout
        vm.prank(teacher1);
        uint256 cashoutId = cashout.requestCashout(classroomId, 10 ether, keccak256("lab supplies"));
        assertEq(uint256(cashout.getRequestStatus(cashoutId)),
                 uint256(ICashoutRequest.RequestStatus.Pending));

        // Step 7: Admin approves cashout (governance = vault address, not teacher)
        vm.prank(address(vault));
        cashout.approveCashout(cashoutId);
        assertEq(uint256(cashout.getRequestStatus(cashoutId)),
                 uint256(ICashoutRequest.RequestStatus.Approved));
    }

    // ===================================================================
    // E2E SCENARIO 2: Multiple Students, Multiple Contributions
    // ===================================================================

    function test_e2e_multiple_students_contribute() public {
        // Setup classroom
        vm.prank(principal);
        uint256 cid = cluster.createClassroom("Chemistry 201", teacher1, 11, 2026, "B");

        // Register 3 devices and students
        address student2 = vm.addr(student2Key);
        address student3 = vm.addr(student3Key);
        bytes32 dev2 = keccak256("chromebook-chem-002");
        bytes32 dev3 = keccak256("chromebook-chem-003");
        bytes32 principal2 = keccak256("hmac-student-002");
        bytes32 principal3 = keccak256("hmac-student-003");

        vm.startPrank(itDir);
        cluster.registerDevice(device1Cert, student1);
        cluster.registerDevice(dev2, student2);
        cluster.registerDevice(dev3, student3);
        vm.stopPrank();

        vm.startPrank(teacher1);
        cluster.grantClassroomRole(cid, student1, IClassroomCluster.ClassroomRole.Student);
        cluster.grantClassroomRole(cid, student2, IClassroomCluster.ClassroomRole.Student);
        cluster.grantClassroomRole(cid, student3, IClassroomCluster.ClassroomRole.Student);
        vm.stopPrank();

        assertEq(cluster.getStudentCount(cid), 3);

        // Each student submits a training contribution
        bytes32[3] memory principals = [studentPrincipal, principal2, principal3];
        bytes32[3] memory devices = [device1Cert, dev2, dev3];
        uint256[3] memory keys = [student1Key, student2Key, student3Key];

        for (uint256 i = 0; i < 3; i++) {
            bytes memory call_ = abi.encodeWithSelector(
                TrainingDataRecorder.submitTrainingData.selector,
                principals[i],
                cid,
                keccak256(abi.encodePacked("correction-", i))
            );

            IForwarder.ForwardRequest memory req = IForwarder.ForwardRequest({
                orgPrincipalId: principals[i],
                classroomId: cid,
                nonce: 0,
                sessionExpiry: block.timestamp + 2700,
                deviceCertHash: devices[i],
                target: address(recorder),
                data: call_
            });

            _executeAsRelayer(req, _signForwardRequest(req, keys[i]));
        }

        assertEq(recorder.getTupleCount(), 3);
    }

    // ===================================================================
    // E2E SCENARIO 3: Device Revocation Mid-Session
    // ===================================================================

    function test_e2e_device_revoked_mid_session() public {
        // Setup
        vm.prank(principal);
        uint256 cid = cluster.createClassroom("Math 301", teacher1, 9, 2026, "");
        vm.prank(itDir);
        cluster.registerDevice(device1Cert, student1);
        vm.prank(teacher1);
        cluster.grantClassroomRole(cid, student1, IClassroomCluster.ClassroomRole.Student);

        // First contribution succeeds
        IForwarder.ForwardRequest memory req1 = IForwarder.ForwardRequest({
            orgPrincipalId: studentPrincipal,
            classroomId: cid,
            nonce: 0,
            sessionExpiry: block.timestamp + 2700,
            deviceCertHash: device1Cert,
            target: address(recorder),
            data: abi.encodeWithSelector(
                TrainingDataRecorder.submitTrainingData.selector,
                studentPrincipal, cid, keccak256("correct")
            )
        });

        _executeAsRelayer(req1, _signForwardRequest(req1, student1Key));
        assertEq(recorder.getTupleCount(), 1);

        // IT revokes device (reported lost/stolen)
        vm.prank(itDir);
        cluster.revokeDevice(device1Cert);

        // Second contribution fails — device revoked
        IForwarder.ForwardRequest memory req2 = IForwarder.ForwardRequest({
            orgPrincipalId: studentPrincipal,
            classroomId: cid,
            nonce: 1,
            sessionExpiry: block.timestamp + 2700,
            deviceCertHash: device1Cert,
            target: address(recorder),
            data: abi.encodeWithSelector(
                TrainingDataRecorder.submitTrainingData.selector,
                studentPrincipal, cid, keccak256("should-fail")
            )
        });

        bytes memory revokedDeviceSignature = _signForwardRequest(req2, student1Key);
        vm.expectRevert(); // DeviceRevoked
        _executeAsRelayer(req2, revokedDeviceSignature);

        // Only 1 contribution recorded
        assertEq(recorder.getTupleCount(), 1);
    }

    // ===================================================================
    // E2E SCENARIO 4: Student Transfer Between Classrooms
    // ===================================================================

    function test_e2e_student_transfer() public {
        address teacher2 = address(0x4002);

        vm.prank(principal);
        uint256 bio = cluster.createClassroom("Bio 101", teacher1, 9, 2026, "");
        vm.prank(principal);
        uint256 chem = cluster.createClassroom("Chem 201", teacher2, 9, 2026, "");

        // Student starts in Bio
        vm.prank(teacher1);
        cluster.grantClassroomRole(bio, student1, IClassroomCluster.ClassroomRole.Student);
        assertEq(cluster.getStudentCount(bio), 1);
        assertEq(cluster.getStudentCount(chem), 0);

        // Admin transfers student to Chem (atomic)
        vm.prank(principal);
        cluster.transferStudent(student1, bio, chem);

        // Student is now in Chem, not Bio
        assertEq(uint256(cluster.getClassroomRole(bio, student1)),
                 uint256(IClassroomCluster.ClassroomRole.None));
        assertEq(uint256(cluster.getClassroomRole(chem, student1)),
                 uint256(IClassroomCluster.ClassroomRole.Student));
        assertEq(cluster.getStudentCount(bio), 0);
        assertEq(cluster.getStudentCount(chem), 1);
    }

    // ===================================================================
    // E2E SCENARIO 5: Emergency Pause Stops Everything
    // ===================================================================

    function test_e2e_emergency_pause() public {
        // Setup a pending cashout
        vm.prank(principal);
        cluster.createClassroom("Bio 101", teacher1, 10, 2026, "");

        vm.prank(teacher1);
        cashout.requestCashout(0, 5 ether, keccak256("supplies"));

        // Principal triggers emergency pause on vault
        vm.prank(principal);
        vault.emergencyPause();
        assertTrue(vault.isPaused());

        // Cannot propose new cashouts through vault while paused
        vm.prank(principal);
        vm.expectRevert(); // VaultPaused
        vault.proposeCashout(teacher1, 1 ether, keccak256("denied"));

        // Unpause requires 2-of-3
        vm.prank(principal);
        vault.unpause();
        assertTrue(vault.isPaused()); // Still paused (only 1)

        vm.prank(vp);
        vault.unpause();
        assertFalse(vault.isPaused()); // Now unpaused (2-of-3)
    }

    // ===================================================================
    // E2E SCENARIO 6: Privilege Escalation Blocked Across Stack
    // ===================================================================

    function test_e2e_student_cannot_escalate_through_any_contract() public {
        // Setup
        vm.prank(principal);
        cluster.createClassroom("Bio 101", teacher1, 10, 2026, "");
        vm.prank(itDir);
        cluster.registerDevice(device1Cert, student1);
        vm.prank(teacher1);
        cluster.grantClassroomRole(0, student1, IClassroomCluster.ClassroomRole.Student);

        vm.startPrank(student1);

        // Cannot grant self admin
        vm.expectRevert();
        cluster.grantOrgRole(student1, IClassroomCluster.OrgRole.Admin);

        // Cannot create classroom
        vm.expectRevert();
        cluster.createClassroom("Hacked", student1, 0, 0, "");

        // Cannot allocate budget
        vm.expectRevert();
        budget.allocateBudget(0, 1000, 500);

        // Cannot approve cashout
        vm.expectRevert();
        cashout.approveCashout(0);

        // Cannot add relayer
        vm.expectRevert();
        forwarder.addRelayer(student1);

        // Cannot access vault
        vm.expectRevert();
        vault.proposeCashout(student1, 100 ether, keccak256("steal"));

        vm.stopPrank();
    }
}
