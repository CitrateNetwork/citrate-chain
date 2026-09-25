// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {InitialAdmin} from "../../src/lib/InitialAdmin.sol";
import {AppRegistry} from "../../src/defense_prime/AppRegistry.sol";
import {AuditBundleRegistry} from "../../src/defense_prime/AuditBundleRegistry.sol";
import {CrossOrgEnvelope} from "../../src/defense_prime/CrossOrgEnvelope.sol";
import {CrossOrgIndex} from "../../src/defense_prime/CrossOrgIndex.sol";
import {DefensePrimeComplianceRegistry} from "../../src/defense_prime/DefensePrimeComplianceRegistry.sol";
import {DefensePrimeFLScopeIndex} from "../../src/defense_prime/DefensePrimeFLScopeIndex.sol";
import {EntityRegistry} from "../../src/defense_prime/EntityRegistry.sol";
import {MoqRegistry} from "../../src/defense_prime/MoqRegistry.sol";
import {PartProvenanceRegistry} from "../../src/defense_prime/PartProvenanceRegistry.sol";
import {ReleaseManifestRegistry} from "../../src/defense_prime/ReleaseManifestRegistry.sol";
import {RoleGrantTenantIndex} from "../../src/defense_prime/RoleGrantTenantIndex.sol";
import {SponsorEvidenceRegistry} from "../../src/defense_prime/SponsorEvidenceRegistry.sol";
import {SupplierRegistry} from "../../src/defense_prime/SupplierRegistry.sol";
import {TinaWorkpaperRegistry} from "../../src/defense_prime/TinaWorkpaperRegistry.sol";
import {TripwireRegistry} from "../../src/defense_prime/TripwireRegistry.sol";
import {AgentDecisionRegistryV2} from "../../src/rbac/AgentDecisionRegistryV2.sol";
import {ClassificationRegistry} from "../../src/rbac/ClassificationRegistry.sol";
import {ContradictionLedger} from "../../src/rbac/ContradictionLedger.sol";
import {BudgetAllocation} from "../../src/edu/BudgetAllocation.sol";
import {CashoutRequest} from "../../src/edu/CashoutRequest.sol";
import {ClassroomClusterV1} from "../../src/edu/ClassroomClusterV1.sol";
import {ComplianceRegistry} from "../../src/edu/ComplianceRegistry.sol";
import {Forwarder} from "../../src/edu/Forwarder.sol";
import {GuardianTokenRegistry} from "../../src/edu/GuardianTokenRegistry.sol";
import {InstitutionTreeV1} from "../../src/edu/InstitutionTreeV1.sol";
import {OrganizationSBT} from "../../src/cit_agent/OrganizationSBT.sol";
import {AgentSBT} from "../../src/cit_agent/AgentSBT.sol";
import {CapsuleRegistry} from "../../src/cit_agent/CapsuleRegistry.sol";
import {MultisigTimelock2of3} from "../../src/cit_agent/MultisigTimelock2of3.sol";

/// PBA-L2-002 (class sweep): every constructor that seeds governance / owner
/// from an argument refuses the CREATE2 factory, and still accepts a real key.
contract PBA_L2_002_InitialAdminSweep is Test {
    address constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    address constant KEY = address(0xB0B);

    function test_AppRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new AppRegistry(FACTORY, address(0xE11));
    }

    function test_AppRegistry_realKeyDeploys() public {
        assertGt(address(new AppRegistry(KEY, address(0xE11))).code.length, 0);
    }

    function test_AuditBundleRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new AuditBundleRegistry(FACTORY);
    }

    function test_AuditBundleRegistry_realKeyDeploys() public {
        assertGt(address(new AuditBundleRegistry(KEY)).code.length, 0);
    }

    function test_CrossOrgEnvelope_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new CrossOrgEnvelope(FACTORY);
    }

    function test_CrossOrgEnvelope_realKeyDeploys() public {
        assertGt(address(new CrossOrgEnvelope(KEY)).code.length, 0);
    }

    function test_CrossOrgIndex_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new CrossOrgIndex(FACTORY);
    }

    function test_CrossOrgIndex_realKeyDeploys() public {
        assertGt(address(new CrossOrgIndex(KEY)).code.length, 0);
    }

    function test_DefensePrimeComplianceRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new DefensePrimeComplianceRegistry(FACTORY);
    }

    function test_DefensePrimeComplianceRegistry_realKeyDeploys() public {
        assertGt(address(new DefensePrimeComplianceRegistry(KEY)).code.length, 0);
    }

    function test_DefensePrimeFLScopeIndex_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new DefensePrimeFLScopeIndex(FACTORY);
    }

    function test_DefensePrimeFLScopeIndex_realKeyDeploys() public {
        assertGt(address(new DefensePrimeFLScopeIndex(KEY)).code.length, 0);
    }

    function test_EntityRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new EntityRegistry(FACTORY);
    }

    function test_EntityRegistry_realKeyDeploys() public {
        assertGt(address(new EntityRegistry(KEY)).code.length, 0);
    }

    function test_MoqRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new MoqRegistry(FACTORY);
    }

    function test_MoqRegistry_realKeyDeploys() public {
        assertGt(address(new MoqRegistry(KEY)).code.length, 0);
    }

    function test_PartProvenanceRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new PartProvenanceRegistry(FACTORY);
    }

    function test_PartProvenanceRegistry_realKeyDeploys() public {
        assertGt(address(new PartProvenanceRegistry(KEY)).code.length, 0);
    }

    function test_ReleaseManifestRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new ReleaseManifestRegistry(FACTORY);
    }

    function test_ReleaseManifestRegistry_realKeyDeploys() public {
        assertGt(address(new ReleaseManifestRegistry(KEY)).code.length, 0);
    }

    function test_RoleGrantTenantIndex_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new RoleGrantTenantIndex(FACTORY);
    }

    function test_RoleGrantTenantIndex_realKeyDeploys() public {
        assertGt(address(new RoleGrantTenantIndex(KEY)).code.length, 0);
    }

    function test_SponsorEvidenceRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new SponsorEvidenceRegistry(FACTORY);
    }

    function test_SponsorEvidenceRegistry_realKeyDeploys() public {
        assertGt(address(new SponsorEvidenceRegistry(KEY)).code.length, 0);
    }

    function test_SupplierRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new SupplierRegistry(FACTORY);
    }

    function test_SupplierRegistry_realKeyDeploys() public {
        assertGt(address(new SupplierRegistry(KEY)).code.length, 0);
    }

    function test_TinaWorkpaperRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new TinaWorkpaperRegistry(FACTORY);
    }

    function test_TinaWorkpaperRegistry_realKeyDeploys() public {
        assertGt(address(new TinaWorkpaperRegistry(KEY)).code.length, 0);
    }

    function test_TripwireRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new TripwireRegistry(FACTORY);
    }

    function test_TripwireRegistry_realKeyDeploys() public {
        assertGt(address(new TripwireRegistry(KEY)).code.length, 0);
    }

    function test_AgentDecisionRegistryV2_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new AgentDecisionRegistryV2(FACTORY);
    }

    function test_AgentDecisionRegistryV2_realKeyDeploys() public {
        assertGt(address(new AgentDecisionRegistryV2(KEY)).code.length, 0);
    }

    function test_ClassificationRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new ClassificationRegistry(FACTORY);
    }

    function test_ClassificationRegistry_realKeyDeploys() public {
        assertGt(address(new ClassificationRegistry(KEY)).code.length, 0);
    }

    function test_ContradictionLedger_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new ContradictionLedger(FACTORY);
    }

    function test_ContradictionLedger_realKeyDeploys() public {
        assertGt(address(new ContradictionLedger(KEY)).code.length, 0);
    }

    function test_BudgetAllocation_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new BudgetAllocation(FACTORY);
    }

    function test_BudgetAllocation_realKeyDeploys() public {
        assertGt(address(new BudgetAllocation(KEY)).code.length, 0);
    }

    function test_CashoutRequest_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new CashoutRequest(FACTORY, 100);
    }

    function test_CashoutRequest_realKeyDeploys() public {
        assertGt(address(new CashoutRequest(KEY, 100)).code.length, 0);
    }

    function test_ClassroomClusterV1_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new ClassroomClusterV1(FACTORY);
    }

    function test_ClassroomClusterV1_realKeyDeploys() public {
        assertGt(address(new ClassroomClusterV1(KEY)).code.length, 0);
    }

    function test_ComplianceRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new ComplianceRegistry(FACTORY, address(0x7EE));
    }

    function test_ComplianceRegistry_realKeyDeploys() public {
        assertGt(address(new ComplianceRegistry(KEY, address(0x7EE))).code.length, 0);
    }

    function test_Forwarder_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new Forwarder(FACTORY, address(0xC1), address(0xA1));
    }

    function test_Forwarder_realKeyDeploys() public {
        assertGt(address(new Forwarder(KEY, address(0xC1), address(0xA1))).code.length, 0);
    }

    function test_GuardianTokenRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new GuardianTokenRegistry(FACTORY);
    }

    function test_GuardianTokenRegistry_realKeyDeploys() public {
        assertGt(address(new GuardianTokenRegistry(KEY)).code.length, 0);
    }

    function test_InstitutionTreeV1_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new InstitutionTreeV1(FACTORY);
    }

    function test_InstitutionTreeV1_realKeyDeploys() public {
        assertGt(address(new InstitutionTreeV1(KEY)).code.length, 0);
    }

    function test_OrganizationSBT_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new OrganizationSBT(FACTORY);
    }

    function test_OrganizationSBT_realKeyDeploys() public {
        assertGt(address(new OrganizationSBT(KEY)).code.length, 0);
    }

    function test_AgentSBT_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new AgentSBT(FACTORY, OrganizationSBT(address(0x0A9)));
    }

    function test_AgentSBT_realKeyDeploys() public {
        assertGt(address(new AgentSBT(KEY, OrganizationSBT(address(0x0A9)))).code.length, 0);
    }

    function test_CapsuleRegistry_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new CapsuleRegistry(FACTORY);
    }

    function test_CapsuleRegistry_realKeyDeploys() public {
        assertGt(address(new CapsuleRegistry(KEY)).code.length, 0);
    }

    function test_MultisigTimelock2of3_factoryReverts() public {
        vm.expectRevert(InitialAdmin.InitialAdmin_Create2Factory.selector);
        new MultisigTimelock2of3([address(0x0B1), FACTORY, address(0x0B3)], 1 hours);
    }

    function test_MultisigTimelock2of3_realKeyDeploys() public {
        assertGt(address(new MultisigTimelock2of3([address(0x0B1), KEY, address(0x0B3)], 1 hours)).code.length, 0);
    }

}
