import {
  generateRelationshipType,
  RelationshipClass,
  StepEntityMetadata,
  StepRelationshipMetadata,
} from '@jupiterone/integration-sdk-core';
import { ENTITY_TYPE_SERVICE_VMDR } from '../services';

import { VmdrEntities } from '../vmdr/constants';
import { ENTITY_TYPE_WEBAPP_FINDING } from '../was/constants';

export const SERVICE_ENTITY_DATA_KEY = 'SERVICE_ENTITY_DATA_KEY';

export const STEP_FETCH_FINDING_VULNS = 'fetch-finding-vulns';
export const STEP_FETCH_ASSESSMENTS = 'fetch-assessments';
export const STEP_FETCH_FINDINGS = 'fetch-findings';
export const STEP_BUILD_HOST_FINDING_RELATIONSHIP =
  'build-host-finding-relationship';

/**
 * The _type of Vulnerability when CVE is known.
 */
export const ENTITY_TYPE_CVE_VULNERABILITY = 'cve';

/**
 * The _type of Vulnerability when there are no related CVEs.
 */
export const ENTITY_TYPE_QUALYS_VULNERABILITY = 'qualys_vuln';
export const MAPPED_RELATIONSHIP_TYPE_WEBAPP_FINDING_CVE_VULNERABILITY = generateRelationshipType(
  RelationshipClass.IS,
  ENTITY_TYPE_WEBAPP_FINDING,
  ENTITY_TYPE_CVE_VULNERABILITY,
);
export const MAPPED_RELATIONSHIP_TYPE_WEBAPP_FINDING_QUALYS_VULNERABILITY = generateRelationshipType(
  RelationshipClass.IS,
  ENTITY_TYPE_WEBAPP_FINDING,
  ENTITY_TYPE_QUALYS_VULNERABILITY,
);

export const VulnEntities: Record<string, StepEntityMetadata> = {
  ASSESSMENT: {
    _type: `qualys_assessment`,
    _class: ['Assessment'],
    resourceName: 'Assessment',
    indexMetadata: {
      enabled: true,
    },
  },
  FINDING: {
    _type: `qualys_finding`,
    _class: ['Finding'],
    resourceName: 'Finding',
    indexMetadata: {
      enabled: true,
    },
  },
};

export const VulnRelationships: Record<string, StepRelationshipMetadata> = {
  WEBAPP_FINDING_QUALYS_VULN: {
    _type: MAPPED_RELATIONSHIP_TYPE_WEBAPP_FINDING_QUALYS_VULNERABILITY,
    _class: RelationshipClass.IS,
    sourceType: ENTITY_TYPE_WEBAPP_FINDING,
    targetType: ENTITY_TYPE_QUALYS_VULNERABILITY,
    partial: true,
    indexMetadata: {
      enabled: true,
    },
  },
  WEBAPP_FINDING_CVE_VULN: {
    _type: MAPPED_RELATIONSHIP_TYPE_WEBAPP_FINDING_CVE_VULNERABILITY,
    _class: RelationshipClass.IS,
    sourceType: ENTITY_TYPE_WEBAPP_FINDING,
    targetType: ENTITY_TYPE_CVE_VULNERABILITY,
    partial: true,
    indexMetadata: {
      enabled: true,
    },
  },
  HOST_HAS_ASSESSMENT: {
    _type: `qualys_host_has_assessment`,
    _class: RelationshipClass.HAS,
    sourceType: VmdrEntities.HOST._type,
    targetType: VulnEntities.ASSESSMENT._type,
    indexMetadata: {
      enabled: true,
    },
  },
  SCANNER_PERFORMED_ASSESSMENT: {
    _type: `qualys_scanner_performed_assessment`,
    _class: RelationshipClass.PERFORMED,
    sourceType: ENTITY_TYPE_SERVICE_VMDR,
    targetType: VulnEntities.ASSESSMENT._type,
    indexMetadata: {
      enabled: true,
    },
  },
  HOST_HAS_FINDING: {
    _type: `qualys_host_has_finding`,
    _class: RelationshipClass.HAS,
    sourceType: VmdrEntities.HOST._type,
    targetType: VulnEntities.FINDING._type,
    indexMetadata: {
      enabled: true,
    },
  },
  ASSESSMENT_IDENTIFIED_FINDING: {
    _type: `qualys_assessment_identified_finding`,
    _class: RelationshipClass.IDENTIFIED,
    sourceType: VulnEntities.ASSESSMENT._type,
    targetType: VulnEntities.FINDING._type,
    indexMetadata: {
      enabled: true,
    },
  },
};
