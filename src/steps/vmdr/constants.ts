import {
  generateRelationshipType,
  RelationshipClass,
  RelationshipDirection,
  StepEntityMetadata,
  StepMappedRelationshipMetadata,
  StepRelationshipMetadata,
} from '@jupiterone/integration-sdk-core';
import { ENTITY_TYPE_QUALYS_ACCOUNT } from '../account';

export const Steps = {
  HOSTS: 'fetch-hosts',
  BUILD_HOST_MAPPED_RELATIONSHIP: 'build-host-ec2-gcp-relationship',
};

export const VmdrEntities: Record<string, StepEntityMetadata> = {
  HOST: {
    _type: `qualys_host`,
    _class: ['Host'],
    resourceName: 'Host',
    indexMetadata: {
      enabled: true,
    },
  },
};

export const VmdrRelationships: Record<string, StepRelationshipMetadata> = {
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

export const ENTITY_TYPE_EC2_HOST = 'aws_instance';
export const ENTITY_TYPE_GCP_HOST = 'google_compute_instance';

export const VmdrMappedRelationships: Record<
  string,
  StepMappedRelationshipMetadata
> = {
  HOST_IS_EC2: {
    _type: generateRelationshipType(
      RelationshipClass.IS,
      VmdrEntities.HOST._type,
      ENTITY_TYPE_EC2_HOST,
    ),
    _class: RelationshipClass.IS,
    sourceType: VmdrEntities.HOST._type,
    direction: RelationshipDirection.FORWARD,
    targetType: ENTITY_TYPE_EC2_HOST,
    partial: true,
    indexMetadata: {
      enabled: true,
    },
  },
  HOST_IS_GCP: {
    _type: generateRelationshipType(
      RelationshipClass.IS,
      VmdrEntities.HOST._type,
      ENTITY_TYPE_GCP_HOST,
    ),
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
