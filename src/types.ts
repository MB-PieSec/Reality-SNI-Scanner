export interface ProbeResult {
  hostname: string;
  ok: boolean;
  tlsVersion?: string;
  alpn?: string | false;
  handshakeMs?: number;
  authorized?: boolean;
  issuer?: string;
  error?: string;
  source: "top-sites" | "asn-neighbor" | "ct-log" | "fallback";
}

export interface ScanOptions {
  candidateCount: number;
  concurrency: number;
  port: number;
  timeoutMs: number;
  requireH2: boolean;
  requireTls13: boolean;
  requireAuthorized: boolean;
}
