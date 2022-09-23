import { v4 as uuid } from 'uuid';

import {
  createDirectRelationship,
  createMappedRelationship,
  Entity,
  getRawData,
  IntegrationStep,
  IntegrationStepExecutionContext,
  JobState,
  RelationshipClass,
  RelationshipDirection,
} from '@jupiterone/integration-sdk-core';

import { createQualysAPIClient } from '../../provider';
import { QualysIntegrationConfig } from '../../types';
import { getQualysHost } from '../../util';
import {
  SerializedVulnerabilityFindingKeys,
  VulnerabilityFindingKeysCollector,
} from '../utils';
import {
  DATA_HOST_VULNERABILITY_FINDING_KEYS,
  ENTITY_TYPE_HOST_FINDING,
  STEP_FETCH_SCANNED_HOST_DETAILS,
  STEP_FETCH_SCANNED_HOST_FINDINGS,
  VmdrEntities,
} from '../vmdr/constants';
import { DATA_WEBAPP_VULNERABILITY_FINDING_KEYS } from '../was/constants';
import {
  STEP_FETCH_ASSESSMENTS,
  STEP_FETCH_FINDINGS,
  STEP_FETCH_FINDING_VULNS,
  VulnEntities,
  VulnMappedRelationships,
  VulnRelationships,
} from './constants';
import {
  createAsessmentEntity,
  createFindingVulnerabilityMappedRelationships,
  createVulnerabilityTargetEntities,
  getAssessmentKey,
} from './converters';
import { Scan } from '../../provider/client/types/vmpc/listSCANS';
import { ScanFinding } from '../../provider/client/types/vmpc/listScanResults';
import { getHostKey } from '../vmdr/converters';
import { DATA_VMDR_SERVICE_ENTITY, STEP_FETCH_SERVICES } from '../services';
import { HostAsset } from '../../provider/client/types/assets';

/**
 * This is the number of vulnerabilities that must be traversed before producing
 * a more verbose set of logging.
 */
const VULNERABILTIES_LOG_FREQUENCY = 500;

/**
 * Fetches vulnerability information for each ingested Finding and builds mapped
 * relationships between a Finding and each detected Vulnerability.
 *
 * TODO Handle CWEs in Findings as mapped relationship to Weakness entities
 *
 * TODO Add a resource cache for integration (accessible across invocations) so
 * we don't have to re-load the vuln CVE data. Do not store everything, only
 * that necessary for CVE info.
 *
 * TODO: Consider a FindingUploaderThingy that has a cache/fetches Vulns at
 * threshold, then patches Findings with some vuln details and then adds to
 * jobState.
 *
 * @see `createVulnerabilityTargetEntities`
 */
export async function fetchFindingVulnerabilities({
  logger,
  instance,
  jobState,
}: IntegrationStepExecutionContext<QualysIntegrationConfig>) {
  const qualysHost = getQualysHost(instance.config.qualysApiUrl);
  const apiClient = createQualysAPIClient(logger, instance.config);

  const vulnerabiltyFindingKeysCollector = new VulnerabilityFindingKeysCollector();
  await loadVulnerabilityFindingKeys(
    vulnerabiltyFindingKeysCollector,
    jobState,
  );

  const errorCorrelationId = uuid();

  let totalVulnerabilitiesProcessed = 0;
  let totalFindingsProcessed = 0;
  let totalPageErrors = 0;

  await apiClient.iterateVulnerabilities(
    vulnerabiltyFindingKeysCollector.allQids(),
    async (vuln) => {
      const targetEntities = createVulnerabilityTargetEntities(
        qualysHost,
        vuln,
      );

      const vulnFindingKeys = vulnerabiltyFindingKeysCollector.getVulnerabiltyFindingKeys(
        vuln.QID!,
      );

      if (vulnFindingKeys) {
        for (const findingKey of vulnFindingKeys) {
          if (!jobState.hasKey(findingKey)) {
            logger.warn(
              { qid: vuln.QID, findingKey },
              'Previous ingestion steps failed to store Finding in job state for _key',
            );
          } else {
            const {
              relationships,
              duplicates,
            } = createFindingVulnerabilityMappedRelationships(
              findingKey,
              targetEntities,
            );

            await jobState.addRelationships(relationships);

            if (duplicates.length > 0) {
              logger.warn(
                { qid: vuln.QID, duplicateKeys: duplicates.map((e) => e._key) },
                'Finding appears to have duplicate related vulnerabilities, need to create a better Finding._key?',
              );
            }
          }

          totalFindingsProcessed++;
        }
      } else {
        logger.warn(
          { qid: vuln.QID },
          'Previous ingestion steps failed to associate Finding _keys with vulnerability',
        );
      }

      totalVulnerabilitiesProcessed++;

      // This code is hot and we don't want to be logging all of the time.
      // We largely reduce the number of logs by ensuring that we only log every
      // so often.
      const shouldLogPageVerbose =
        totalVulnerabilitiesProcessed % VULNERABILTIES_LOG_FREQUENCY === 0 &&
        totalVulnerabilitiesProcessed !== 0;

      if (shouldLogPageVerbose) {
        logger.info(
          {
            totalVulnerabilitiesProcessed,
            totalFindingsProcessed,
            totalPageErrors,
          },
          'Processing vulnerabilities...',
        );
      }
    },
    {
      onRequestError(pageIds, err) {
        totalPageErrors++;
        logger.error(
          { pageIds, err, errorCorrelationId, totalPageErrors },
          'Error processing page of vulnerabilities',
        );
      },
    },
  );
}

export async function fetchAssessments({
  logger,
  instance,
  jobState,
}: IntegrationStepExecutionContext<QualysIntegrationConfig>) {
  const apiClient = createQualysAPIClient(logger, instance.config);
  const scannerEntity = (await jobState.getData(
    DATA_VMDR_SERVICE_ENTITY,
  )) as Entity;

  await jobState.iterateEntities(
    { _type: VmdrEntities.HOST._type },
    async (hostEntity) => {
      const host = getRawData<HostAsset>(hostEntity);

      if (!host) logger.info(`Can't get raw data for ${hostEntity._key}`);
      else {
        await apiClient.iterateHostScans(
          host.address as string,
          async (scan) => {
            const assessmentKey = getAssessmentKey(scan.REF);

            const assessmentEntity = createAsessmentEntity(scan);
            if (!(await jobState.hasKey(assessmentKey)))
              await jobState.addEntity(assessmentEntity);

            await jobState.addRelationship(
              createDirectRelationship({
                _class: RelationshipClass.HAS,
                from: hostEntity,
                to: assessmentEntity,
              }),
            );

            const scannerAssessmentRelationship = createDirectRelationship({
              _class: RelationshipClass.PERFORMED,
              from: scannerEntity,
              to: assessmentEntity,
            });

            if (!(await jobState.hasKey(scannerAssessmentRelationship._key)))
              await jobState.addRelationship(scannerAssessmentRelationship);
          },
        );
      }
    },
  );
}

export async function fetchAssessmentResults({
  logger,
  instance,
  jobState,
}: IntegrationStepExecutionContext<QualysIntegrationConfig>) {
  const apiClient = createQualysAPIClient(logger, instance.config);

  await jobState.iterateEntities(
    { _type: VmdrEntities.ASSESSMENT._type },
    async (assessmentEntity) => {
      const scan = getRawData<Scan>(assessmentEntity);

      if (!scan) logger.info(`Can't get raw data for ${assessmentEntity._key}`);
      else {
        await apiClient.iterateScanResults(scan.REF, async (finding) => {
          const hostKey = getHostKey(finding.ip);
          const hostEntity = await jobState.findEntity(hostKey);
          if (hostEntity) {
            const host = getRawData<HostAsset>(hostEntity);

            if (host) {
              const assessmentFindingRelationship = createMappedRelationship({
                _class: RelationshipClass.IDENTIFIED,
                _mapping: {
                  sourceEntityKey: assessmentEntity._key,
                  relationshipDirection: RelationshipDirection.FORWARD,
                  targetFilterKeys: [
                    ['_type', 'qid', 'hostId', 'port', 'protocol', 'ssl'],
                  ],
                  targetEntity: {
                    _type: ENTITY_TYPE_HOST_FINDING,
                    qid: finding.qid,
                    port: finding.port,
                    protocol: finding.protocol,
                    ssl: finding.ssl === 'yes' ? 1 : 0,
                    hostId: host.qwebHostId,
                  },
                  skipTargetCreation: true,
                },
              });

              const hostFindingRelationship = createMappedRelationship({
                _class: RelationshipClass.HAS,
                _mapping: {
                  sourceEntityKey: hostEntity._key,
                  relationshipDirection: RelationshipDirection.FORWARD,
                  targetFilterKeys: [
                    ['_type', 'qid', 'hostId', 'port', 'protocol', 'ssl'],
                  ],
                  targetEntity: {
                    _type: ENTITY_TYPE_HOST_FINDING,
                    qid: finding.qid,
                    port: finding.port,
                    protocol: finding.protocol,
                    ssl: finding.ssl === 'yes' ? 1 : 0,
                    hostId: host.qwebHostId,
                  },
                  skipTargetCreation: true,
                },
              });

              console.log(assessmentFindingRelationship);
              console.log(hostFindingRelationship);

              if (!(await jobState.hasKey(assessmentFindingRelationship._key)))
                await jobState.addRelationship(assessmentFindingRelationship);
              if (!(await jobState.hasKey(hostFindingRelationship._key)))
                await jobState.addRelationship(hostFindingRelationship);
            }
          }
        });
      }
    },
  );
}

export async function buildHostFindingRelationship({
  logger,
  instance,
  jobState,
}: IntegrationStepExecutionContext<QualysIntegrationConfig>) {
  await jobState.iterateEntities(
    { _type: VmdrEntities.FINDING._type },
    async (findingEntity) => {
      const finding = getRawData<ScanFinding>(findingEntity);

      if (!finding) logger.info(`Can't get raw data for ${findingEntity._key}`);
      else {
        const hostEntity = await jobState.findEntity(getHostKey(finding.ip));

        if (hostEntity) {
          const hostFindingRelationship = createDirectRelationship({
            _class: RelationshipClass.HAS,
            from: hostEntity,
            to: findingEntity,
          });

          if (!(await jobState.hasKey(hostFindingRelationship._key)))
            await jobState.addRelationship(hostFindingRelationship);
        }
      }
    },
  );
}

/**
 * Answers a map of QID -> `Finding._key[]` from all steps that collected
 * Finding entities.
 *
 * The Finding ingestion steps will store a mapping of QID to each
 * `Finding._key` associated with the vulnerability. This allows
 * `STEP_FETCH_FINDING_VULNS` to know which vulnerabilities to fetch and to
 * which Finding entites to map relationships.
 */
async function loadVulnerabilityFindingKeys(
  collector: VulnerabilityFindingKeysCollector,
  jobState: JobState,
): Promise<void> {
  for (const dataKey of [
    DATA_WEBAPP_VULNERABILITY_FINDING_KEYS,
    DATA_HOST_VULNERABILITY_FINDING_KEYS,
  ]) {
    collector.loadSerialized(await popFindingKeys(jobState, dataKey));
  }
}

/**
 * Fetches from `jobState` and deserializes the map of QID -> `Finding._key[]`
 * identified by `dataKey`. The data will be removed from the `jobState` to free
 * up resources.
 */
async function popFindingKeys(jobState: JobState, dataKey: string) {
  const findingKeys =
    ((await jobState.getData(dataKey)) as SerializedVulnerabilityFindingKeys) ||
    [];
  await jobState.setData(dataKey, []);
  return findingKeys;
}

export const vulnSteps: IntegrationStep<QualysIntegrationConfig>[] = [
  {
    id: STEP_FETCH_FINDING_VULNS,
    name: 'Fetch Finding Vulnerability Details',
    entities: [],
    relationships: [
      VulnRelationships.HOST_FINDING_QUALYS_VULN,
      VulnRelationships.HOST_FINDING_CVE_VULN,
      VulnRelationships.WEBAPP_FINDING_QUALYS_VULN,
      VulnRelationships.WEBAPP_FINDING_CVE_VULN,
    ],
    dependsOn: [],
    executionHandler: fetchFindingVulnerabilities,
    dependencyGraphId: 'last',
  },
  {
    id: STEP_FETCH_ASSESSMENTS,
    name: 'Fetch Assessments',
    entities: [VulnEntities.ASSESSMENT],
    relationships: [
      VulnRelationships.HOST_HAS_ASSESSMENT,
      VulnRelationships.SCANNER_PERFORMED_ASSESSMENT,
    ],
    dependsOn: [STEP_FETCH_SCANNED_HOST_DETAILS, STEP_FETCH_SERVICES],
    executionHandler: fetchAssessments,
  },
  {
    id: STEP_FETCH_FINDINGS,
    name: 'Fetch Findings',
    entities: [],
    relationships: [],
    mappedRelationships: [
      VulnMappedRelationships.HOST_HAS_FINDING,
      VulnMappedRelationships.ASSESSMENT_IDENTIFIED_FINDING,
    ],
    dependsOn: [
      STEP_FETCH_ASSESSMENTS,
      STEP_FETCH_SCANNED_HOST_FINDINGS,
      STEP_FETCH_SCANNED_HOST_DETAILS,
    ],
    executionHandler: fetchAssessmentResults,
  },
];
