/**
 * Configuration for the temporary Stage-2 Xray instances.
 *
 * Two short-lived processes are used per candidate: a "server" that terminates
 * a REALITY inbound on a free loopback port with the candidate as its dest,
 * and a "client" that dials that inbound. Upload traffic is pushed through the
 * pair so the measured speed comes from a real REALITY tunnel rather than a
 * plain socket.
 *
 * The key pair below is fixed, hard-coded and used ONLY by these throwaway
 * test instances. It never appears in the dest/serverNames suggestion printed
 * at the end, so it is not a credential anybody needs to rotate — it only
 * exists so both sides of a two-process test agree on something.
 *
 * Encoding note: Xray parses `privateKey`/`publicKey` with Go's
 * base64.RawURLEncoding and requires exactly 32 bytes. Both values here are
 * 43 characters drawn from [A-Za-z0-9], which decodes identically under the
 * raw URL-safe and raw standard alphabets, so they work with every Xray build
 * regardless of which spelling it was compiled against.
 */

export const REALITY_TEST_PRIVATE_KEY = "eJVUNNH62lv0FnchEtrhOkG6nzztY6WZX4s9j1dHJ0I";
export const REALITY_TEST_PUBLIC_KEY = "hOXNwoBqG4eAJcKAOSq4XWCkSM7KmN32B2rHZAVhDTM";
/** Hex, 8 chars — spells "mono". Zero-padded to 8 bytes identically on both sides. */
export const REALITY_TEST_SHORT_ID = "6d6f6e6f";
/** Throwaway client id for the test tunnel only. */
export const REALITY_TEST_UUID = "2f7c9e1a-5b64-4d38-9a01-7c5e2b8d4f66";
/** Chrome fingerprint: the server rejects ClientHellos without X25519MLKEM768. */
export const REALITY_TEST_FINGERPRINT = "chrome";

export interface ServerConfigParams {
  /** Candidate domain: the REALITY dest and the only allowed serverName. */
  hostname: string;
  /** Loopback port the temporary server listens on. */
  listenPort: number;
  /** Port the server dials on the candidate (the port Stage 1 probed). */
  destPort: number;
}

export interface ClientConfigParams {
  hostname: string;
  /** Loopback port the client's local inbound listens on (we push data here). */
  inboundPort: number;
  /** Loopback port of the temporary REALITY server. */
  serverPort: number;
  /** Loopback port of this process's sink server (where uploads land). */
  sinkPort: number;
}

/** Minimal Xray config: VLESS + REALITY inbound, freedom outbound. */
export function buildServerConfig(params: ServerConfigParams): unknown {
  const { hostname, listenPort, destPort } = params;
  return {
    log: { loglevel: "info" },
    inbounds: [
      {
        listen: "127.0.0.1",
        port: listenPort,
        protocol: "vless",
        settings: {
          clients: [{ id: REALITY_TEST_UUID, flow: "xtls-rprx-vision" }],
          decryption: "none",
        },
        streamSettings: {
          network: "tcp",
          security: "reality",
          realitySettings: {
            show: true,
            dest: `${hostname}:${destPort}`,
            xver: 0,
            serverNames: [hostname],
            privateKey: REALITY_TEST_PRIVATE_KEY,
            shortIds: [REALITY_TEST_SHORT_ID],
          },
        },
      },
    ],
    outbounds: [{ protocol: "freedom", tag: "direct" }],
  };
}

/**
 * Client config. Its inbound is a dokodemo-door, which forwards every byte it
 * receives to a fixed address through the outbound — so pushing raw TCP into
 * that port is enough to send data through the tunnel, with no proxy protocol
 * to speak on our side.
 */
export function buildClientConfig(params: ClientConfigParams): unknown {
  const { hostname, inboundPort, serverPort, sinkPort } = params;
  return {
    log: { loglevel: "info" },
    inbounds: [
      {
        listen: "127.0.0.1",
        port: inboundPort,
        protocol: "dokodemo-door",
        settings: {
          address: "127.0.0.1",
          port: sinkPort,
          network: "tcp",
        },
      },
    ],
    outbounds: [
      {
        protocol: "vless",
        settings: {
          vnext: [
            {
              address: "127.0.0.1",
              port: serverPort,
              users: [{ id: REALITY_TEST_UUID, encryption: "none", flow: "xtls-rprx-vision" }],
            },
          ],
        },
        streamSettings: {
          network: "tcp",
          security: "reality",
          realitySettings: {
            serverName: hostname,
            fingerprint: REALITY_TEST_FINGERPRINT,
            publicKey: REALITY_TEST_PUBLIC_KEY,
            shortId: REALITY_TEST_SHORT_ID,
            spiderX: "/",
          },
        },
      },
    ],
  };
}
