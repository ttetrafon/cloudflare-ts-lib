export type SessionRow = {
  sid: string;
  jkt: string;
  refresh_hash: string;
  prev_refresh_hash: string | null;
  device_label: string | null;
  created_at: number;
  last_seen: number;
  expires_abs: number;
};

