import type { OnTransactionHandler } from '@metamask/snaps-sdk';
import { SeverityLevel } from '@metamask/snaps-sdk';
import { Banner, Box, Divider, Heading, Row, Text } from '@metamask/snaps-sdk/jsx';

import type { EngineResult } from './engine';
import { buildRequest, callEngine, chainOf, ENGINE_URL } from './engine';

const TITLE: Record<string, string> = {
  block: 'Nguy hiểm: nên huỷ giao dịch này',
  warn: 'Cảnh báo: địa chỉ nhận có dấu hiệu rủi ro',
  ok: 'Không thấy dấu hiệu Address Misuse',
};

export function render(r: EngineResult) {
  const risky = r.decision === 'block' || r.decision === 'warn';
  return (
    <Box>
      <Heading>Address Misuse Guard</Heading>
      <Banner
        title={TITLE[r.decision] ?? 'Không rõ'}
        severity={r.decision === 'block' ? 'danger' : r.decision === 'warn' ? 'warning' : 'success'}
      >
        <Text>{`Điểm rủi ro R = ${r.score === null ? '-' : r.score.toFixed(1)} / 100`}</Text>
      </Banner>
      {risky && r.types && r.types.length > 0 ? (
        <Row label="Loại">
          <Text>{r.types.join(', ')}</Text>
        </Row>
      ) : null}
      <Divider />
      {r.reasons.slice(0, 4).map((x) => (
        <Text>{`• ${x}`}</Text>
      ))}
      {r.missed_nets && r.missed_nets.length > 0 ? (
        <Text color="muted">{`Chưa kiểm được mạng: ${r.missed_nets.join(', ')}`}</Text>
      ) : null}
    </Box>
  );
}

export const onTransaction: OnTransactionHandler = async ({ transaction, chainId }) => {
  const chain = chainOf(chainId);
  if (chain === null) {
    return {
      content: (
        <Box>
          <Heading>Address Misuse Guard</Heading>
          <Text>{`Mạng ${chainId} chưa được hỗ trợ, không kiểm tra.`}</Text>
        </Box>
      ),
    };
  }
  const result = await callEngine(buildRequest(transaction as never, chain));
  if (result === null) {
    return {
      content: (
        <Box>
          <Heading>Address Misuse Guard</Heading>
          <Text>{`Không kết nối được Risk Engine (${ENGINE_URL}). Giao dịch chưa được kiểm tra.`}</Text>
        </Box>
      ),
    };
  }
  const content = render(result);
  return result.decision === 'block' || result.decision === 'warn'
    ? { content, severity: SeverityLevel.Critical }
    : { content };
};
