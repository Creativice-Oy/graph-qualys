import {
  generateRelationshipType,
  RelationshipClass,
  RelationshipDirection,
  StepEntityMetadata,
  StepMappedRelationshipMetadata,
  StepRelationshipMetadata,
} from '@jupiterone/integration-sdk-core';
import { ENTITY_TYPE_QUALYS_ACCOUNT } from '../account';

import { ENTITY_TYPE_SERVICE_VMDR } from '../services';

export const STEP_FETCH_SCANNED_HOST_IDS = 'fetch-scanned-host-ids';
export const STEP_FETCH_SCANNED_HOST_DETAILS = 'fetch-scanned-host-details';
export const STEP_FETCH_SCANNED_HOST_FINDINGS = 'fetch-scanned-host-detections';

export const DATA_SCANNED_HOST_IDS = 'DATA_SCANNED_HOST_IDS';

/**
 * Detection target values pulled from a host asset that serve as additional
 * information for building Finding entities during host detection processing.
 */
export const DATA_HOST_ASSET_TARGETS = 'DATA_HOST_ASSET_TARGETS';

export const DATA_HOST_VULNERABILITY_FINDING_KEYS =
  'DATA_HOST_VULNERABILITY_FINDING_KEYS';

export const ENTITY_TYPE_HOST_FINDING = 'qualys_host_finding';

export const ENTITY_TYPE_DISCOVERED_HOST = 'discovered_host';
export const ENTITY_TYPE_EC2_HOST = 'aws_instance';
export const ENTITY_TYPE_GCP_HOST = 'google_compute_instance';

export const RELATIONSHIP_TYPE_SERVICE_HOST_FINDING = generateRelationshipType(
  RelationshipClass.IDENTIFIED,
  ENTITY_TYPE_SERVICE_VMDR,
  ENTITY_TYPE_HOST_FINDING,
);

export const VmdrEntities: Record<string, StepEntityMetadata> = {
  HOST_FINDING: {
    _type: ENTITY_TYPE_HOST_FINDING,
    _class: 'Finding',
    resourceName: 'Host Detection',
    partial: true,
    indexMetadata: {
      enabled: true,
    },
  },
  HOST: {
    _type: `qualys_host`,
    _class: ['Host'],
    resourceName: 'Host',
    indexMetadata: {
      enabled: true,
    },
  },
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

export const MAPPED_RELATIONSHIP_TYPE_HOST_IS_HOST = generateRelationshipType(
  RelationshipClass.IS,
  VmdrEntities.HOST._type,
  ENTITY_TYPE_DISCOVERED_HOST,
);
export const MAPPED_RELATIONSHIP_TYPE_HOST_IS_EC2_HOST = generateRelationshipType(
  RelationshipClass.IS,
  VmdrEntities.HOST._type,
  ENTITY_TYPE_EC2_HOST,
);

export const MAPPED_RELATIONSHIP_TYPE_HOST_IS_GCP_HOST = generateRelationshipType(
  RelationshipClass.IS,
  VmdrEntities.HOST._type,
  ENTITY_TYPE_GCP_HOST,
);

export const VmdrRelationships: Record<string, StepRelationshipMetadata> = {
  SERVICE_HOST_FINDING: {
    _type: RELATIONSHIP_TYPE_SERVICE_HOST_FINDING,
    _class: RelationshipClass.IDENTIFIED,
    sourceType: ENTITY_TYPE_SERVICE_VMDR,
    targetType: ENTITY_TYPE_HOST_FINDING,
    partial: true,
    indexMetadata: {
      enabled: true,
    },
  },
  ACCOUNT_HAS_HOST: {
    _type: `qualys_account_has_host`,
    _class: RelationshipClass.HAS,
    sourceType: ENTITY_TYPE_QUALYS_ACCOUNT,
    targetType: VmdrEntities.HOST._type,
    indexMetadata: {
      enabled: true,
    },
  },
};

export const VmdrMappedRelationships: Record<
  string,
  StepMappedRelationshipMetadata
> = {
  HOST_IS_HOST: {
    _type: MAPPED_RELATIONSHIP_TYPE_HOST_IS_HOST,
    _class: RelationshipClass.IS,
    sourceType: VmdrEntities.HOST._type,
    direction: RelationshipDirection.FORWARD,
    targetType: ENTITY_TYPE_DISCOVERED_HOST,
    partial: true,
    indexMetadata: {
      enabled: true,
    },
  },
  HOST_EC2_HOST: {
    _type: MAPPED_RELATIONSHIP_TYPE_HOST_IS_EC2_HOST,
    _class: RelationshipClass.IS,
    sourceType: VmdrEntities.HOST._type,
    direction: RelationshipDirection.FORWARD,
    targetType: ENTITY_TYPE_EC2_HOST,
    partial: true,
    indexMetadata: {
      enabled: true,
    },
  },
  HOST_GCP_HOST: {
    _type: MAPPED_RELATIONSHIP_TYPE_HOST_IS_GCP_HOST,
    _class: RelationshipClass.IS,
    sourceType: VmdrEntities.HOST._type,
    direction: RelationshipDirection.FORWARD,
    targetType: ENTITY_TYPE_GCP_HOST,
    partial: true,
    indexMetadata: {
      enabled: true,
    },
  },
};
