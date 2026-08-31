#!/usr/bin/env node
// PreToolUse 훅 — 에이전트의 도구 호출을 코드 수준에서 검사·차단 (보안 하네스의 한 축)
//  stdin: {"session_id","tool_name","tool_input",...}  → 차단 시 permissionDecision=deny 출력
//  규칙:
//   (1) 결제/주문/체크아웃 URL 이동 차단
//   (2) 결제/구매 버튼 클릭 차단
//   (3) 스크립트 기반 데이터 유출(외부 fetch/XHR/쿠키 전송) 차단  ← 보안 H2
//   (4) 세션당 로그인(비밀번호 입력) 1회 초과 차단 (계정 잠금 방지)
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const BLOCKED_URL = /(\/order\b|\/orders?\/|\/checkout|\/payment|\/pay\b|\/buy\b|\/purchase|toss\.im\/payments|kakaopay|naverpay|inicis|kcp\.co\.kr|nicepay)/i;
const BLOCKED_CLICK = /(바로구매|구매하기|결제하기|결제|주문하기|주문 완료|주문완료|결제 진행|바로 구매|즉시구매|Buy now|Checkout|Place order)/i;
const PASSWORD_FIELD = /(비밀번호|password|passwd|pwd)/i;
const MAX_LOGIN_ATTEMPTS = 1;

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => (input += d));
process.stdin.on('end', () => {
  let ev; try { ev = JSON.parse(input); } catch { process.exit(0); }
  const tool = ev.tool_name || '';
  const i = ev.tool_input || {};
  const deny = (reason) => {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: `가드레일 차단: ${reason}` } }));
    process.exit(0);
  };
  const t = tool.replace(/^mcp__playwright__/, '');
  const text = JSON.stringify(i);

  if (t === 'browser_navigate' && BLOCKED_URL.test(i.url || '')) deny(`결제/주문 URL 이동 금지 (${i.url})`);
  if ((t === 'browser_click' || t === 'browser_mouse_click_xy' || t === 'browser_hover') && BLOCKED_CLICK.test(`${i.element || ''} ${i.ref || ''}`)) deny(`결제/구매 버튼 클릭 금지 (${i.element})`);

  // 보안 H2: 스크립트 기반 데이터 유출 차단 — 외부(비-localhost) 전송, 쿠키·토큰 탈취
  if (t === 'browser_evaluate' || t === 'browser_run_code' || t === 'browser_run_code_unsafe') {
    const code = i.function || i.expression || i.code || text;
    if (/(location\.(href|assign|replace)|\.submit\(|click\(\))/.test(code) && (BLOCKED_URL.test(text) || BLOCKED_CLICK.test(text))) deny('스크립트로 결제/주문 동작 시도');
    const hasNetSend = /(fetch\s*\(|XMLHttpRequest|sendBeacon|new\s+WebSocket|new\s+EventSource|import\s*\()/i.test(code);
    const extUrl = /https?:\/\/(?!(127\.0\.0\.1|localhost|0\.0\.0\.0)[:/])[a-z0-9.-]+/i.test(code);
    if (hasNetSend && extUrl) deny('보안: 스크립트에서 외부 도메인으로 네트워크 전송 시도(데이터 유출 방지)');
    if (/(document\.cookie|localStorage|sessionStorage)/i.test(code) && hasNetSend) deny('보안: 쿠키/스토리지(자격증명)를 네트워크로 전송하려는 시도 차단');
  }

  // 로그인 시도 카운터: 비밀번호 필드 입력을 세션당 1회로 제한
  const isPw = (t === 'browser_type' && PASSWORD_FIELD.test(i.element || '')) || (t === 'browser_fill_form' && PASSWORD_FIELD.test(text));
  if (isPw) {
    const dir = join(tmpdir(), 'webagent-guard'); mkdirSync(dir, { recursive: true });
    const f = join(dir, `login-${ev.session_id || 'nosession'}.json`);
    let n = 0; if (existsSync(f)) { try { n = JSON.parse(readFileSync(f, 'utf8')).n || 0; } catch { n = 0; } }
    if (n >= MAX_LOGIN_ATTEMPTS) deny(`로그인 입력은 세션당 ${MAX_LOGIN_ATTEMPTS}회만 허용 (계정 잠금 방지). 실패 원인을 보고하고 사람에게 인계하라`);
    writeFileSync(f, JSON.stringify({ n: n + 1, at: new Date().toISOString() }));
  }
  process.exit(0); // allow
});
