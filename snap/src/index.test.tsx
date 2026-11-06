import { expect } from '@jest/globals';
import { installSnap } from '@metamask/snaps-jest';
import { createServer, type Server } from 'http';

// Risk Engine giả trên đúng cổng Snap gọi (127.0.0.1:8711); trả kết quả theo địa chỉ `to`.
const RESULTS: Record<string, unknown> = {
  '0x627306090abab3a6e1400e9345bc60c78a8bef57': {
    decision: 'block', score: 92.5, types: ['T5'], hard_rule: 'leaked_key',
    reasons: ['ví nhận nằm trong danh sách lộ private key'], missed_nets: [],
  },
  '0x1111111111111111111111111111111111111111': {
    decision: 'ok', score: 3.1, types: [], reasons: ['không có dấu hiệu'], missed_nets: ['polygon'],
  },
};
let server: Server;
let last: Record<string, unknown> = {};

beforeAll(async () => {
  server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      last = JSON.parse(body || '{}');
      const out = RESULTS[String(last.to).toLowerCase()];
      res.writeHead(out ? 200 : 500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(out ?? { error: 'x' }));
    });
  });
  await new Promise<void>((r) => server.listen(8711, '127.0.0.1', () => r()));
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

describe('onTransaction', () => {
  it('flags a leaked-key recipient as critical and sends chain + value', async () => {
    const { onTransaction } = await installSnap();
    const res = await onTransaction({
      chainId: 'eip155:1', to: '0x627306090abaB3A6e1400e9345bC60c78a8BEf57', value: '0xde0b6b3a7640000', data: '0x',
    });
    const result = (res.response as { result: { severity?: string } }).result;
    expect(result.severity).toBe('critical');
    expect(last.chain).toBe('eth');
    expect(BigInt(String(last.value))).toBe(10n ** 18n);
    const ui = JSON.stringify(res.getInterface().content);
    expect(ui).toContain('Nguy hiểm');
    expect(ui).toContain('92.5');
    expect(ui).toContain('lộ private key');
  });

  it('shows ok without severity and lists missed networks', async () => {
    const { onTransaction } = await installSnap();
    const res = await onTransaction({ chainId: 'eip155:56', to: '0x1111111111111111111111111111111111111111' });
    const result = (res.response as { result: { severity?: string } }).result;
    expect(result.severity).toBeUndefined();
    expect(last).toMatchObject({ chain: 'bsc' });
    expect(JSON.stringify(res.getInterface().content)).toContain('polygon');
  });

  it('fails open when the engine errors', async () => {
    const { onTransaction } = await installSnap();
    const res = await onTransaction({ chainId: 'eip155:1', to: '0x2222222222222222222222222222222222222222' });
    expect((res.response as { result: { severity?: string } }).result.severity).toBeUndefined();
    expect(JSON.stringify(res.getInterface().content)).toContain('Không kết nối được Risk Engine');
  });

  it('skips unsupported chains', async () => {
    const { onTransaction } = await installSnap();
    const res = await onTransaction({ chainId: 'eip155:31337', to: '0x1111111111111111111111111111111111111111' });
    expect(JSON.stringify(res.getInterface().content)).toContain('chưa được hỗ trợ');
  });
});
