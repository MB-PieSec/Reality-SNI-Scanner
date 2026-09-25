export interface ProbeResult {
  hostname: string;
  ok: boolean;
  tlsVersion?: string;
  alpn?: string | false;
  handshakeMs?: number;
  authorized?: boolean;
  issuer?: string;
  error?: string;
  source: "top-sites" | "asn-neighbor" | "ct-log" | "fallback" | "ct-subdomain";
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

export type CTDiscoveryMode = "seeds" | "main-domains";

/** A Stage-1 winner handed to Stage 2. */
export interface RealityTestCandidate {
  hostname: string;
  handshakeMs?: number;
}

export interface RealityTestOptions {
  /** Upload payload size in KB. */
  uploadKb: number;
  /** Parallel tunnel tests; deliberately capped low (a few Xray processes each). */
  concurrency: number;
  /** Resolved path to the Xray binary to launch. */
  xrayPath: string;
  /** Port Stage 1 probed on the candidates; the REALITY dest uses it too. */
  destPort: number;
}

export interface RealityTestResult {
  hostname: string;
  ok: boolean;
  handshakeMs?: number;
  /** Measured upload rate through the temporary REALITY tunnel, in kilobits/s. */
  realityUploadKbps?: number;
  uploadBytes?: number;
  /** Wall-clock time for the measured upload, including tunnel setup. */
  elapsedMs?: number;
  error?: string;
}
