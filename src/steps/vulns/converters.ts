import {
  createIntegrationEntity,
  createMappedRelationship,
  generateRelationshipType,
  MappedRelationship,
  parseTimePropertyValue,
  RelationshipClass,
  RelationshipDirection,
  TargetEntityProperties,
} from '@jupiterone/integration-sdk-core';

import { vmpc } from '../../provider/client';
import { ScanFinding } from '../../provider/client/types/vmpc/listScanResults';
import { Scan } from '../../provider/client/types/vmpc/listScans';
import { CveList } from '../../provider/client/types/vmpc/listVulnerabilities';
import { ENTITY_TYPE_HOST_FINDING } from '../vmdr/constants';
import {
  // ENTITY_TYPE_CVE_VULNERABILITY,
  ENTITY_TYPE_QUALYS_VULNERABILITY,
  VulnEntities,
} from './constants';

/**
 * Creates N mapped relationships, one for each `TargetEntityProperties`
 * provided.
 *
 * @param findingEntity the Entity representing the host detection Finding
 * @param targetEntityProperties an Array of `TargetEntityProperties`
 * representing each vulnerability associated with the Finding
 */
export function createFindingVulnerabilityMappedRelationships(
  findingKey: string,
  targetEntityProperties: TargetEntityProperties[],
): { relationships: MappedRelationship[]; duplicates: MappedRelationship[] } {
  const seenRelationshipKeys = new Set<string>();
  const duplicates: MappedRelationship[] = [];
  const relationships: MappedRelationship[] = [];

  for (const targetEntity of targetEntityProperties) {
    const relationship = createMappedRelationship({
      _class: RelationshipClass.IS,
      _type: generateRelationshipType(
        RelationshipClass.IS,
        ENTITY_TYPE_HOST_FINDING,
        targetEntity._type!,
      ),
      _mapping: {
        relationshipDirection: RelationshipDirection.FORWARD,
        sourceEntityKey: findingKey,
        targetFilterKeys: [['_type', '_key']],
        targetEntity,
      },
    });

    if (seenRelationshipKeys.has(relationship._key)) {
      duplicates.push(relationship);
      continue;
    }

    relationships.push(relationship);
    seenRelationshipKeys.add(relationship._key);
  }
  return { relationships, duplicates };
}

export function getAssessmentKey(id: string): string {
  return `qualys_assessment:${id}`;
}

export function createAsessmentEntity(data: Scan) {
  return createIntegrationEntity({
    entityData: {
      source: data,
      assign: {
        _type: VulnEntities.ASSESSMENT._type,
        _key: getAssessmentKey(data.REF),
        _class: VulnEntities.ASSESSMENT._class,
        ref: data.REF,
        type: data.TYPE,
        name: data.TITLE,
        userLogin: data.USER_LOGIN,
        launchDatetime: parseTimePropertyValue(data.LAUNCH_DATETIME),
        duration: data.DURATION,
        processingPriority: data.PROCESSING_PRIORITY,
        processed: data.PROCESSED,
        statusState: data.STATUS.STATE,
        target: data.TARGET,
        category: 'Vulnerability Scan',
        summary: data.TITLE,
        internal: true,
      },
    },
  });
}

export function getFindingKey(id: string): string {
  return `qualys_finding${id}`;
}

export function createFindingEntity(data: ScanFinding) {
  return createIntegrationEntity({
    entityData: {
      source: data,
      assign: {
        _type: VulnEntities.FINDING._type,
        _key: getFindingKey(data.qid.toString()),
        _class: VulnEntities.FINDING._class,
        name: data.title,
        ip: data.ip,
        dns: data.dns,
        netbios: data.netbios,
        os: data.os,
        ipStatus: data.ip_status,
        qid: data.qid,
        title: data.title,
        type: data.type,
        severity: data.severity,
        port: data.port,
        protocol: data.protocol,
        fqdn: data.fqdn,
        ssl: data.ssl,
        cveId: data.cve_id,
        vendorReference: data.vendor_reference,
        bugtraqId: data.bugtraq_id,
        threat: data.threat,
        impact: data.impact || undefined,
        solution: data.solution,
        associatedMalware: data.associated_malware,
        results: data.results,
        pciVuln: data.pci_vuln,
        instance: data.instance,
        category: data.category,
        numericSeverity: parseInt(data.severity),
        open: !!data.exploitability,
        exploitability: parseInt(data.severity),
      },
    },
  });
}

/**
 * Creates a set of mapped relationship target entities for each Vulnerability.
 *
 * When a vuln is related to one or more CVEs, the properties will map to
 * `_type: ENTITY_TYPE_CVE_VULNERABILITY, _key: '<cve id>'`. In the case where a
 * vulnerability has no CVEs, the properties will map to `_type:
 * ENTITY_TYPE_QUALYS_VULNERABILITY, _key: 'vuln-qid:<qid>'`.
 *
 * @param qualysHost the host name of the Qualys server, i.e.
 * qg3.apps.qualys.com, to be used in building `webLink` values to the Qualys UI
 * @param vuln the vulnerability data from the Qualys Knowledgebase
 */
export function createVulnerabilityTargetEntities(
  qualysHost: string,
  vuln: vmpc.Vuln,
): TargetEntityProperties[] {
  const properties: TargetEntityProperties[] = [];

  // We opted to comment out the CVE target entity creation and purely use
  // qualys_vuln entities. We may revisit this so I'm leaving it commented out
  // in case we want to turn this back on.

  // for (const cve of toArray(vuln.CVE_LIST?.CVE)) {
  //   if (cve.ID) {
  //     properties.push({
  //       _class: 'Vulnerability',
  //       _type: ENTITY_TYPE_CVE_VULNERABILITY,
  //       _key: cve.ID.toLowerCase(),
  //       qid: vuln.QID,
  //       id: cve.ID,
  //       name: cve.ID,
  //       displayName: cve.ID,
  //       webLink: cve.URL,
  //       cvssScore: vuln.CVSS?.BASE,
  //       cvssScoreV3: vuln.CVSS_V3?.BASE,
  //     });
  //   }
  // }

  properties.push({
    _class: 'Vulnerability',
    _type: ENTITY_TYPE_QUALYS_VULNERABILITY,
    _key: `vuln-qid:${vuln.QID}`,
    qid: vuln.QID,
    id: String(vuln.QID!),
    name: vuln.TITLE,
    displayName: vuln.TITLE,
    webLink: buildQualysGuardVulnWebLink(qualysHost, vuln.QID!),
    severityLevel: vuln.SEVERITY_LEVEL, // raw value, not normalized as it is on `Finding.numericSeverity`

    cveIds: cveListToCveIds(vuln.CVE_LIST),
    cvssScore: vuln.CVSS?.BASE,
    cvssScoreV3: vuln.CVSS_V3?.BASE,

    vulnType: vuln.VULN_TYPE,
    solution: vuln.SOLUTION,
    discoveryRemote: vuln.DISCOVERY?.REMOTE,
    category: vuln.CATEGORY,
  });

  return properties;
}

export function cveListToCveIds(cveList: CveList | undefined | null): string[] {
  // check that cveList and cveList.CVE are both defined
  if (!cveList || !cveList.CVE) {
    return [];
  }
  // case where CVE is an array
  if (Array.isArray(cveList.CVE)) {
    const cveIds: string[] = [];
    for (const cve of cveList.CVE) {
      if (typeof cve.ID === 'string') {
        cveIds.push(cve.ID);
      }
    }
    return cveIds;
  }
  // case where CVE is a single bugtraq object
  if (typeof cveList.CVE.ID === 'string') {
    return [cveList.CVE.ID];
  }

  return [];
}

function buildQualysGuardVulnWebLink(qualysHost: string, qid: number): string {
  return `https://qualysguard.${qualysHost}/fo/common/vuln_info.php?id=${qid}`;
}
