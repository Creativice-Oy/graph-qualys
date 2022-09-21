import { chunk } from 'lodash';
import { v4 as uuid } from 'uuid';

import {
  Entity,
  IntegrationInfoEventName,
  IntegrationStep,
  IntegrationStepExecutionContext,
} from '@jupiterone/integration-sdk-core';

import { createQualysAPIClient } from '../../provider';
import { QWebHostId } from '../../provider/client';
import {
  HostDetection,
  ListScannedHostIdsFilters,
} from '../../provider/client/types/vmpc';
import {
  CalculatedIntegrationConfig,
  QualysIntegrationConfig,
} from '../../types';
import { buildKey } from '../../util';
import { DATA_VMDR_SERVICE_ENTITY, STEP_FETCH_SERVICES } from '../services';
import { VulnerabilityFindingKeysCollector } from '../utils';
import {
  DATA_HOST_ASSET_TARGETS,
  DATA_HOST_VULNERABILITY_FINDING_KEYS,
  DATA_SCANNED_HOST_IDS,
  STEP_FETCH_SCANNED_HOST_DETAILS,
  STEP_FETCH_SCANNED_HOST_FINDINGS,
  STEP_FETCH_SCANNED_HOST_IDS,
  VmdrEntities,
  VmdrMappedRelationships,
} from './constants';
import {
  createHostFindingEntity,
  createServiceScansDiscoveredHostAssetRelationship,
  createServiceScansEC2HostAssetRelationship,
  createServiceScansGCPHostAssetRelationship,
  getEC2HostAssetArn,
  getGCPHostProjectId,
  getHostAssetTargets,
} from './converters';
import { HostAssetTargetsMap } from './types';

/**
 * This is the number of pages that must be traversed before producing a more
 * verbose set of logging. The host detections code is hot and we don't want to
 * log too frequently.
 */
const HOST_DETECTIONS_PAGE_LOG_FREQUENCY = 10000;

/**
 * Fetches the set of scanned host IDs that will be processed by the
 * integration. This step may be changed to reduce the set of processed hosts.
 */
export async function fetchTest({
  logger,
  instance,
  jobState,
}: IntegrationStepExecutionContext<QualysIntegrationConfig>) {
  const apiClient = createQualysAPIClient(logger, instance.config);

  const filters: ListScannedHostIdsFilters = {
    vm_processed_after: instance.config.minScannedSinceISODate,
    vm_processed_before: instance.config.maxScannedSinceISODate,
  };

  const loggerFetch = logger.child({ filters });

  let loggedIdsDataType = false;
  const hostIds: QWebHostId[] = [];
  await apiClient.iterateTest(
    (pageOfIds) => {
      for (const hostId of pageOfIds) {
        if (!loggedIdsDataType && typeof hostId !== 'number') {
          loggerFetch.info(
            { hostId, type: typeof hostId },
            'Data type of host id is not number',
          );
          loggedIdsDataType = true;
        }
        hostIds.push(hostId);
      }
      loggerFetch.info(
        { numScannedHostIds: hostIds.length },
        'Fetched page of scanned host IDs',
      );
    },
    {
      filters,
    },
  );

  await apiClient.iterateScansTest();

  await apiClient.iterateScanReportTest();
}

export const testSteps: IntegrationStep<QualysIntegrationConfig>[] = [
  {
    id: 'fetch-test',
    name: 'Fetch Test',
    entities: [],
    relationships: [],
    dependsOn: [],
    executionHandler: fetchTest,
  },
];
