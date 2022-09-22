import {
  createIntegrationEntity,
  parseTimePropertyValue,
} from '@jupiterone/integration-sdk-core';
import { VmdrEntities } from './constants';
import { Host } from '../../provider/client/types/vmpc/listHosts';

export function getHostKey(id: string): string {
  return `qualys_host:${id}`;
}

export function createHostEntity(data: Host) {
  return createIntegrationEntity({
    entityData: {
      source: data,
      assign: {
        _type: VmdrEntities.HOST._type,
        _key: getHostKey(data.IP),
        _class: VmdrEntities.HOST._class,
        id: data.ID.toString(),
        ip: data.IP,
        name: data.IP,
        trackingMethod: data.TRACKING_METHOD,
        dns: data.DNS,
        cloudProvider: data.CLOUD_PROVIDER,
        cloudService: data.CLOUD_SERVICE,
        cloudResourceId: data.CLOUD_RESOURCE_ID,
        ec2InstanceId: data.EC2_INSTANCE_ID,
        os: data.OS,
        qgHostId: data.QG_HOSTID,
        lastVulnScanDatetime: parseTimePropertyValue(
          data.LAST_VULN_SCAN_DATETIME,
        ),
        lastVmScannedDate: parseTimePropertyValue(data.LAST_VM_SCANNED_DATE),
      },
    },
  });
}
