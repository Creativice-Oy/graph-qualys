export type ScanResult = (ScanHeader | ScanJob | ScanFinding | ScanHost)[];

export type ScanHeader = {
  scan_report_template_title: string;
  result_date: string;
  company: string;
  add1: string;
  add2: string;
  city: string;
  state: string;
  country: string;
  zip: string;
  name: string;
  username: string;
  role: string;
};

export type ScanJob = {
  launch_date: string;
  active_hosts: string;
  total_hosts: string;
  type: string;
  status: string;
  reference: string;
  scanner_appliance: string;
  duration: string;
  scan_title: string;
  ips: string;
  excluded_ips: string;
  option_profile: string;
};

export type ScanFinding = {
  ip: string;
  dns: string;
  netbios: null;
  os: string;
  ip_status: string;
  qid: number;
  title: string;
  type: string;
  severity: string;
  port: string;
  protocol: string;
  fqdn: string;
  ssl: string;
  cve_id?: string;
  vendor_reference?: string;
  bugtraq_id?: string;
  threat: string;
  impact: string;
  solution: string;
  exploitability?: string;
  associated_malware?: string;
  results: string;
  pci_vuln: string;
  instance?: string;
  category: string;
};

export type ScanHost = {
  target_distribution_across_scanner_appliances: string;
};
