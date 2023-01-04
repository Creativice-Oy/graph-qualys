export type Scan = {
  REF: string;
  TYPE: string;
  TITLE: string;
  USER_LOGIN: string;
  LAUNCH_DATETIME: string;
  DURATION: string;
  PROCESSING_PRIORITY: string;
  PROCESSED: number;
  STATUS: {
    STATE: string;
  };
  TARGET: string;
};

export type ScanResponse = {
  SCAN_LIST_OUTPUT?: {
    RESPONSE?: {
      DATETIME: string;
      SCAN_LIST?: {
        SCAN: Scan[] | Scan;
      };
    };
  };
};
