/**
 * Phần không phụ thuộc MetaMask: map chain, dựng yêu cầu, gọi Risk Engine cục bộ (`address_misuse.wallet.api`).
 * Mọi logic chấm điểm nằm ở engine Python (Module 2–3); Snap chỉ hiển thị.
 */

export const ENGINE_URL = 'http://127.0.0.1:8711/check';
export const ENGINE_TIMEOUT_MS = 3000;

/** CAIP-2 `eip155:<id>` → tên mạng trong engine (`config.NETWORKS`). */
export const CHAINS: Record<string, string> = {
  '1': 'eth',
  '56': 'bsc',
  '42161': 'arb',
  '10': 'op',
  '8453': 'base',
  '137': 'polygon',
  '11155111': 'sepolia',
  '97': 'bsc_testnet',
};

export function chainOf(caip: string): string | null {
  const [ns, id] = caip.split(':');
  if (ns !== 'eip155' || id === undefined) {
    return null;
  }
  return CHAINS[id] ?? null;
}

export type CheckRequest = {
  to: string | null;
  chain: string;
  value: string;
  data: string;
  authorizations: string[];
};

export type EngineResult = {
  decision: 'ok' | 'warn' | 'block' | 'unsupported';
  score: number | null;
  types?: string[];
  hard_rule?: string | null;
  reasons: string[];
  missed_nets?: string[];
  ms_total?: number;
};

type TxLike = {
  to?: string | null;
  value?: string;
  data?: string;
  input?: string;
  authorizationList?: { address?: string }[];
};

export function buildRequest(tx: TxLike, chain: string): CheckRequest {
  const auths = (tx.authorizationList ?? [])
    .map((a) => a.address)
    .filter((a): a is string => typeof a === 'string');
  return {
    to: tx.to ?? null,
    chain,
    value: tx.value ?? '0x0',
    data: tx.data ?? tx.input ?? '0x',
    authorizations: auths,
  };
}

/** Gọi engine; lỗi mạng hoặc quá giờ → `null` (fail-open: không chặn người dùng vì engine không chạy). */
export async function callEngine(
  req: CheckRequest,
  url: string = ENGINE_URL,
  timeoutMs: number = ENGINE_TIMEOUT_MS,
): Promise<EngineResult | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
      signal: ctrl.signal,
    });
    if (!res.ok) {
      return null;
    }
    return (await res.json()) as EngineResult;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
