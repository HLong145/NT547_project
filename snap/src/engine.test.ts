import { buildRequest, chainOf } from './engine';

describe('chainOf', () => {
  it('maps supported CAIP-2 ids and rejects others', () => {
    expect(chainOf('eip155:1')).toBe('eth');
    expect(chainOf('eip155:56')).toBe('bsc');
    expect(chainOf('eip155:31337')).toBeNull();
    expect(chainOf('solana:mainnet')).toBeNull();
  });
});

describe('buildRequest', () => {
  it('passes value as hex, falls back to input, keeps 7702 delegates', () => {
    const r = buildRequest(
      { to: '0xAb', value: '0xde0b6b3a7640000', input: '0x1234', authorizationList: [{ address: '0xd' }, {}] },
      'eth',
    );
    expect(r).toEqual({ to: '0xAb', chain: 'eth', value: '0xde0b6b3a7640000', data: '0x1234', authorizations: ['0xd'] });
  });

  it('handles contract creation (no to)', () => {
    expect(buildRequest({ data: '0x60' }, 'bsc').to).toBeNull();
  });
});
