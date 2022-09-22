import {
  createDirectRelationship,
  Entity,
  getRawData,
  IntegrationStep,
  IntegrationStepExecutionContext,
  RelationshipClass,
} from '@jupiterone/integration-sdk-core';

import { createQualysAPIClient } from '../../provider';
import { QualysIntegrationConfig } from '../../types';
import {
  Steps,
  VmdrEntities,
  VmdrMappedRelationships,
  VmdrRelationships,
} from './constants';
import { createHostEntity } from './converters';
import { DATA_ACCOUNT_ENTITY, STEP_FETCH_ACCOUNT } from '../account';
import { Host } from '../../provider/client/types/vmpc/listHosts';

export async function fetchHosts({
  logger,
  instance,
  jobState,
}: IntegrationStepExecutionContext<QualysIntegrationConfig>) {
  const apiClient = createQualysAPIClient(logger, instance.config);
  const accountEntity = (await jobState.getData(DATA_ACCOUNT_ENTITY)) as Entity;

  await apiClient.iterateHosts(async (host) => {
    const hostEntity = await jobState.addEntity(createHostEntity(host));

    await jobState.addRelationship(
      createDirectRelationship({
        _class: RelationshipClass.HAS,
        from: accountEntity,
        to: hostEntity,
      }),
    );
  });
}

export async function mapHostToEc2GcpRelationship({
  jobState,
}: IntegrationStepExecutionContext<QualysIntegrationConfig>) {
  await jobState.iterateEntities(
    { _type: VmdrEntities.HOST._type },
    async (hostEntity) => {
      const host = getRawData<Host>(hostEntity);

      if (host) {
        console.log(host);
      }

      return Promise.resolve();
    },
  );
}

export const hostDetectionSteps: IntegrationStep<QualysIntegrationConfig>[] = [
  {
    id: Steps.HOSTS,
    name: 'Fetch Hosts',
    entities: [VmdrEntities.HOST],
    relationships: [VmdrRelationships.ACCOUNT_HAS_HOST],
    dependsOn: [STEP_FETCH_ACCOUNT],
    executionHandler: fetchHosts,
  },
  {
    id: Steps.BUILD_HOST_MAPPED_RELATIONSHIP,
    name: 'Build Host and GCP/EC2 Relationship',
    entities: [],
    relationships: [],
    mappedRelationships: [
      VmdrMappedRelationships.HOST_IS_EC2,
      VmdrMappedRelationships.HOST_IS_GCP,
    ],
    dependsOn: [Steps.HOSTS],
    executionHandler: mapHostToEc2GcpRelationship,
  },
];
