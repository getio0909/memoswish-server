import '../../../scripts/legacy-environment.cjs';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { spawnOwned, stopOwned, waitOwned } from './processes.mjs';

const binary = resolve(process.env.MEMOSWISH_INTEROP_BIN ?? '../../target/debug/memoswishd');
const root = await mkdtemp(join(tmpdir(), 'memoswish-p312-interop-'));
const environment = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('MEMOSWISH_') && k !== 'DATABASE_URL'));
environment.RUST_LOG = 'info,sqlx=warn';
const children = new Set();
const revisions = ['2025-06-18', '2025-11-25'];
const delay = ms => new Promise(r => setTimeout(r, ms));
async function launch(oauth) {
  const directory = join(root, oauth ? 'oauth' : 'http');
  const config = join(root, oauth ? 'oauth.toml' : 'http.toml');
  await writeFile(config, `data_dir = ${JSON.stringify(directory)}\nbind = "127.0.0.1:0"\nseed_demo = false\nmode = "${oauth ? 'multi_tenant' : 'single_user'}"\nregistration_open = true\n${oauth ? '[oauth]\nenabled = true\nissuer = "https://learn.example"\npublic_base_url = "https://learn.example"\nmcp_resource = "https://learn.example/mcp"\n' : ''}[tts]\nauto_detect_espeak = false\n`);
  const owned = spawnOwned(children, binary, ['--config', config, 'serve'], { env: environment, stdio: ['ignore', 'pipe', 'pipe'] }, oauth ? 'OAuth daemon' : 'HTTP daemon');
  const { child } = owned;
  for (let i = 0; i < 200; i++) {
    const match = owned.output.toString().replace(/\x1b\[[0-9;]*m/g, '').match(/listening.*addr=(127\.0\.0\.1:\d+)/);
    if (match && (await fetch(`http://${match[1]}/readyz`)).ok) return `http://${match[1]}`;
    assert.equal(child.exitCode, null, 'daemon exited before readiness');
    assert.equal(child.signalCode, null, 'daemon was signalled before readiness');
    await delay(100);
  }
  throw new Error('daemon readiness exceeded fixture budget');
}
async function qualify(transport, revision, label) {
  const client = new Client({ name: 'memoswish-independent-interop', version: '1' }, { supportedProtocolVersions: [revision], versionNegotiation: { mode: 'legacy' } });
  try {
    await client.connect(transport);
    assert.equal(client.getNegotiatedProtocolVersion(), revision);
    assert.equal(client.getServerVersion().name, 'memoswishd');
    assert.equal(client.getServerVersion().title, 'Memoswish MCP');
    assert.match(client.getInstructions(), /^Memoswish \(忆刷\)/);
    const capabilities = client.getServerCapabilities();
    for (const supported of ['tools', 'resources', 'prompts']) assert.ok(capabilities[supported]);
    for (const unsupported of ['logging', 'tasks', 'elicitation']) assert.equal(capabilities[unsupported], undefined);
    const tools = await client.listTools();
    assert.ok(tools.tools.some(t => t.name === 'deck_import_status' && t.inputSchema.type === 'object'));
    const result = await client.callTool({ name: 'deck_list', arguments: {} });
    assert.equal(result.isError, false);
    assert.ok(Array.isArray(result.structuredContent.result));
    const failure = await client.callTool({ name: 'card_get', arguments: { card_id: 'foreign-or-missing' } });
    assert.equal(failure.isError, true);
    if (!label.includes('OAuth')) {
      const call = async (name, args) => {
        const result = await client.callTool({ name, arguments: args });
        assert.equal(result.isError, false, name + ': ' + JSON.stringify(result));
        return result.structuredContent;
      };
      const deck = await call('deck_create', { title: 'Private authoring ' + revision, language: 'en' });
      const draft = { deck_id: deck.id, front: { title: 'Question' }, back: { title: 'Answer' }, language: 'en' };
      const saved = await call('card_save', { card: draft, publish: false });
      assert.equal(saved.content.publication, 'draft');
      const published = await call('card_publish', { card_id: saved.id, expected_revision: saved.revision, publish: true });
      assert.equal(published.content.publication, 'published');
      assert.equal(published.revision, saved.revision + 1);
      const report = await call('card_report', { card_id: saved.id, observed_revision: published.revision, text: 'Verify this answer', sources: [] });
      assert.equal(report.observed_revision, published.revision);
      for (const publish of [false, true]) {
        const batch = await call('card_upsert', { cards: [draft], content_lifecycle: true, publish });
        assert.equal(batch.result[0].content.publication, publish ? 'published' : 'draft');
        const sliced = await call('material_slice', { deck_id: deck.id, text: 'New :: Answer', commit: true, content_lifecycle: true, publish });
        assert.equal(sliced.cards[0].content.publication, publish ? 'published' : 'draft');
      }
      console.log('PASS independent P3.1 draft/save/publish/report and explicit lifecycle flags: ' + label + ' ' + revision);
    }
    const resources = await client.listResources();
    assert(resources.resources.every(resource => resource.uri.startsWith('memoswish://')));
    if (!label.includes('OAuth')) {
      assert(resources.resources.some(resource => resource.uri === 'memoswish://stats'));
      const stats = await client.readResource({ uri: 'memoswish://stats' });
      assert.equal(stats.contents[0].uri, 'memoswish://stats');
    }
    await client.listPrompts();
    console.log(`PASS TS 2.4.0 ${label} ${revision}: negotiation, capabilities, schema, structured result, domain error, resources, prompts`);
  } finally { await client.close(); }
}
async function oauthFlow(base) {
  // HTTPS 元数据使用显式 loopback 测试代理映射，不访问外部域名。
  const local = url => base + new URL(url, 'https://learn.example').pathname + new URL(url, 'https://learn.example').search;
  const send = (url, init = {}) => fetch(local(url), { redirect: 'manual', ...init });
  const json = async (url, body) => {
    const r = await send(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    assert.ok(r.ok, `JSON fixture endpoint failed: ${new URL(url, base).pathname} ${r.status}`);
    return r.json();
  };
  const form = (url, values, cookie) => send(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(cookie ? { Cookie: cookie } : {}) }, body: new URLSearchParams(values) });
  const protectedMetadata = await (await send('/.well-known/oauth-protected-resource/mcp')).json();
  assert.equal(protectedMetadata.resource, 'https://learn.example/mcp');
  const metadata = await (await send('/.well-known/oauth-authorization-server')).json();
  assert.ok(metadata.code_challenge_methods_supported.includes('S256'));
  await json('/v1/auth/register', { email: 'interop@example.test', password: 'synthetic-password123', display_name: 'Interop' });
  const client = await json(metadata.registration_endpoint, { client_name: 'Independent fixture', redirect_uris: ['http://127.0.0.1/callback'], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'] });
  const verifier = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG';
  const state = 'independent-fixture-state';
  const authorization = new URL(metadata.authorization_endpoint);
  authorization.search = new URLSearchParams({ client_id: client.client_id, response_type: 'code', redirect_uri: 'http://127.0.0.1/callback', resource: protectedMetadata.resource, scope: 'content:read', state, code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url') });
  const browser = async response => {
    assert.equal(response.status, 200);
    const html = await response.text();
    const field = name => { const value = html.match(new RegExp(`name="${name}" value="([^"]+)"`)); assert.ok(value, `missing browser field ${name}`); return value[1]; };
    return { request_id: field('request_id'), csrf: field('csrf'), cookie: response.headers.get('set-cookie').split(';')[0] };
  };
  let b = await browser(await send(authorization));
  b = await browser(await form('/oauth/login', { request_id: b.request_id, csrf: b.csrf, email: 'interop@example.test', password: 'synthetic-password123' }, b.cookie));
  const approval = await form('/oauth/authorize', { request_id: b.request_id, csrf: b.csrf, decision: 'approve' }, b.cookie);
  assert.equal(approval.status, 303);
  const redirect = new URL(approval.headers.get('location'));
  assert.equal(redirect.searchParams.get('state'), state);
  assert.equal(redirect.searchParams.get('iss'), 'https://learn.example');
  const exchange = await form(metadata.token_endpoint, { grant_type: 'authorization_code', client_id: client.client_id, code: redirect.searchParams.get('code'), redirect_uri: 'http://127.0.0.1/callback', resource: protectedMetadata.resource, code_verifier: verifier });
  assert.equal(exchange.status, 200);
  let tokens = await exchange.json();
  for (const revision of revisions) await qualify(new StreamableHTTPClientTransport(new URL(base + '/mcp'), { requestInit: { headers: { Authorization: `Bearer ${tokens.access_token}` } } }), revision, 'HTTP OAuth code+S256');
  const rpc = (token, name) => send('/mcp', { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'tools/call', params: { name, arguments: {} } }) });
  const insufficient = await rpc(tokens.access_token, 'deck_create');
  assert.equal(insufficient.status, 403);
  assert.match(insufficient.headers.get('www-authenticate'), /insufficient_scope/);
  const wrongAudience = await form(metadata.token_endpoint, { grant_type: 'refresh_token', client_id: client.client_id, refresh_token: tokens.refresh_token, resource: 'https://foreign.example/mcp' });
  assert.equal(wrongAudience.status, 400);
  const refreshed = await form(metadata.token_endpoint, { grant_type: 'refresh_token', client_id: client.client_id, refresh_token: tokens.refresh_token, resource: protectedMetadata.resource });
  assert.equal(refreshed.status, 200);
  tokens = await refreshed.json();
  assert.equal((await rpc(tokens.access_token, 'deck_list')).status, 200);
  const revoked = await form(metadata.revocation_endpoint, { client_id: client.client_id, token: tokens.access_token, token_type_hint: 'access_token' });
  assert.equal(revoked.status, 200);
  assert.equal((await rpc(tokens.access_token, 'deck_list')).status, 401);
  console.log('PASS independent OAuth discovery, registration, browser login/consent, S256, refresh, audience, scope challenge, revocation');
}
try {
  for (const revision of revisions) await qualify(new StdioClientTransport({ command: binary, args: ['--data-dir', join(root, `stdio-${revision}`), 'mcp-stdio'], env: environment, stderr: 'pipe', maxBufferSize: 16 * 1024 * 1024 }), revision, 'stdio');
  const base = await launch(false);
  for (const revision of revisions) await qualify(new StreamableHTTPClientTransport(new URL(base + '/mcp')), revision, 'HTTP');
  await oauthFlow(await launch(true));
  const inspectorConfig = join(root, 'inspector.json');
  await writeFile(inspectorConfig, JSON.stringify({mcpServers:{candidate:{command:binary,args:['--data-dir',join(root,'inspector'),'mcp-stdio'],protocolEra:'legacy'}}}));
  const inspectorEnvironment = {...environment};
  delete inspectorEnvironment.MCP_CATALOG_PATH;
  const inspector = spawnOwned(children, process.execPath, [resolve('node_modules/@modelcontextprotocol/inspector/clients/cli/build/index.js'), '--config', inspectorConfig, '--server', 'candidate', '--method', 'tools/list', '--format', 'json'], {env:inspectorEnvironment,stdio:['ignore','pipe','pipe']}, 'Inspector');
  // 工具目录可能超过诊断预算；流式检查标记并只保留跨块所需的尾部。
  const marker = 'deck_import_status';
  let inspectorHasStatus = false;
  let inspectorTail = '';
  inspector.child.stdout.on('data', bytes => {
    const text = inspectorTail + bytes.toString();
    inspectorHasStatus ||= text.includes(marker);
    inspectorTail = text.slice(-marker.length);
  });
  const inspectorExit = await waitOwned(inspector);
  assert.equal(inspectorExit.code,0,'Inspector host smoke failed');
  assert.ok(inspectorHasStatus);
  console.log('PASS Inspector 2.14.0 independent host smoke: tools/list');
} finally {
  try {
    const results = await Promise.allSettled([...children].map(c => stopOwned(c)));
    const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
    if (failures.length) throw new AggregateError(failures, 'fixture subprocess cleanup failed');
  } finally { await rm(root, { recursive: true, force: true }); }
}
