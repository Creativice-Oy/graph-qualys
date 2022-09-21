export type Host = {
  ID: number;
  IP: string;
  TRACKING_METHOD: string;
  DNS: string;
  DNS_DATA: {
    HOSTNAME: string;
    DOMAIN: string;
    FQDN: string;
  };
  CLOUD_PROVIDER: string;
  CLOUD_SERVICE: string;
  CLOUD_RESOURCE_ID: string;
  EC2_INSTANCE_ID: string;
  OS: string;
  QG_HOSTID: string;
  LAST_VULN_SCAN_DATETIME: string;
  LAST_VM_SCANNED_DATE: string;
  LAST_VM_AUTH_SCANNED_DATE: string;
};

export type HostResponse = {
  HOST_LIST_OUTPUT: {
    RESPONSE: {
      DATETIME: string;
      HOST_LIST: {
        HOST: Host[];
      };
    };
  };
};
