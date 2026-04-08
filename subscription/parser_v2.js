// @ts-nocheck
import { CONFIG } from '../config.js';

const MAX_SUBSCRIPTION_BYTES = 2 * 1024 * 1024;
const MAX_RECURSION_DEPTH = 3;
const NODE_SCHEMES = [
  'anytls://', 'hysteria://', 'hysteria2://', 'hy2://',
  'socks5://', 'socks://', 'ss://', 'ssr://', 'trojan://', 'tuic://', 'vless://', 'vmess://'
];

function decodeNodeName(encodedName, fallback = 'Unnamed') {
  if (!encodedName) return fallback;
  try {
    let decoded = encodedName;
    try { decoded = decodeURIComponent(decoded); } catch {}
    try { decoded = decodeURIComponent(decoded); } catch {}
    if (/^[A-Za-z0-9+/=]+$/.test(decoded)) {
      try {
        const raw = atob(decoded);
        const bytes = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i += 1) bytes[i] = raw.charCodeAt(i);
        const text = new TextDecoder('utf-8').decode(bytes);
        if (/^[\x20-\x7E\u4E00-\u9FFF]+$/.test(text)) decoded = text;
      } catch {}
    }
    try {
      const utf8Decoded = decodeURIComponent(escape(decoded));
      if (utf8Decoded !== decoded) decoded = utf8Decoded;
    } catch {}
    return decoded || fallback;
  } catch {
    return encodedName || fallback;
  }
}

function base64DecodeSmart(str) {
  let result = str;
  try { result = decodeURIComponent(result); } catch {}
  try { result = decodeURIComponent(escape(atob(result))); }
  catch {
    try { result = atob(result); } catch {}
  }
  if (/^[A-Za-z0-9+/=]+$/.test(result) && result.length > 16) {
    try { result = decodeURIComponent(escape(atob(result))); }
    catch {
      try { result = atob(result); } catch {}
    }
  }
  return result;
}

function ensureArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function isNodeScheme(value = '') {
  const lower = value.toLowerCase();
  return NODE_SCHEMES.some(scheme => lower.startsWith(scheme));
}

function getIndent(line) {
  return line.match(/^\s*/)?.[0]?.length || 0;
}

function isCommentOrEmpty(line) {
  const trimmed = line.trim();
  return !trimmed || trimmed.startsWith('#');
}

function parseScalar(value) {
  const trimmed = String(value ?? '').trim();
  if (!trimmed) return '';
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    return parseInlineYamlObject(trimmed);
  }
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  if (trimmed === 'null') return null;
  if (/^-?\d+(\.\d+)?$/.test(trimmed)) return Number(trimmed);
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    return trimmed.slice(1, -1).split(',').map(part => parseScalar(part)).filter(item => item !== '');
  }
  return trimmed;
}

function splitTopLevel(text, delimiter) {
  const parts = [];
  let current = '';
  let braceDepth = 0;
  let bracketDepth = 0;
  let quote = null;

  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    const prev = i > 0 ? text[i - 1] : '';

    if ((char === '"' || char === "'") && prev !== '\\') {
      if (quote === char) {
        quote = null;
      } else if (!quote) {
        quote = char;
      }
      current += char;
      continue;
    }

    if (!quote) {
      if (char === '{') braceDepth += 1;
      else if (char === '}') braceDepth -= 1;
      else if (char === '[') bracketDepth += 1;
      else if (char === ']') bracketDepth -= 1;
      else if (char === delimiter && braceDepth === 0 && bracketDepth === 0) {
        parts.push(current.trim());
        current = '';
        continue;
      }
    }

    current += char;
  }

  if (current.trim()) {
    parts.push(current.trim());
  }

  return parts;
}

function parseInlineYamlObject(value) {
  const inner = value.slice(1, -1).trim();
  if (!inner) return {};

  const result = {};
  splitTopLevel(inner, ',').forEach(entry => {
    const colonIndex = entry.indexOf(':');
    if (colonIndex === -1) return;
    const key = entry.slice(0, colonIndex).trim();
    const rawValue = entry.slice(colonIndex + 1).trim();
    result[key] = parseScalar(rawValue);
  });

  return result;
}

function parseYamlKeyValue(content) {
  const index = content.indexOf(':');
  if (index === -1) return [content.trim(), undefined];
  const key = content.slice(0, index).trim();
  const rawValue = content.slice(index + 1);
  const value = rawValue.trim() ? parseScalar(rawValue) : undefined;
  return [key, value];
}

function parseYamlBlock(lines, startIndex, indent) {
  let index = startIndex;
  while (index < lines.length && isCommentOrEmpty(lines[index])) index += 1;
  if (index >= lines.length || getIndent(lines[index]) < indent) return [undefined, index];
  return lines[index].trim().startsWith('- ')
    ? parseYamlList(lines, index, indent)
    : parseYamlMap(lines, index, indent);
}

function parseYamlList(lines, startIndex, indent) {
  const result = [];
  let index = startIndex;
  while (index < lines.length) {
    const line = lines[index];
    if (isCommentOrEmpty(line)) { index += 1; continue; }
    const currentIndent = getIndent(line);
    if (currentIndent < indent || !line.trim().startsWith('- ')) break;
    const content = line.trim().slice(2);
    if (!content) {
      const [nestedValue, nextIndex] = parseYamlBlock(lines, index + 1, currentIndent + 2);
      result.push(nestedValue);
      index = nextIndex;
      continue;
    }
    if (content.startsWith('{') && content.endsWith('}')) {
      result.push(parseInlineYamlObject(content));
      index += 1;
      continue;
    }
    if (content.includes(':')) {
      const [key, value] = parseYamlKeyValue(content);
      const item = {};
      if (value !== undefined) item[key] = value;
      else {
        const [nestedValue, nextIndex] = parseYamlBlock(lines, index + 1, currentIndent + 2);
        item[key] = nestedValue;
        index = nextIndex - 1;
      }
      const [rest, nextIndex] = parseYamlMap(lines, index + 1, currentIndent + 2);
      if (rest && typeof rest === 'object' && !Array.isArray(rest)) Object.assign(item, rest);
      result.push(item);
      index = nextIndex;
      continue;
    }
    result.push(parseScalar(content));
    index += 1;
  }
  return [result, index];
}

function parseYamlMap(lines, startIndex, indent) {
  const result = {};
  let index = startIndex;
  while (index < lines.length) {
    const line = lines[index];
    if (isCommentOrEmpty(line)) { index += 1; continue; }
    const currentIndent = getIndent(line);
    if (currentIndent < indent || line.trim().startsWith('- ')) break;
    const [key, value] = parseYamlKeyValue(line.trim());
    if (value !== undefined) {
      result[key] = value;
      index += 1;
      continue;
    }
    const [nestedValue, nextIndex] = parseYamlBlock(lines, index + 1, currentIndent + 2);
    result[key] = nestedValue;
    index = nextIndex;
  }
  return [result, index];
}

function normalizeClashProxy(proxy) {
  if (!proxy || typeof proxy !== 'object') return null;
  const type = String(proxy.type || '').toLowerCase();
  const name = decodeNodeName(String(proxy.name || proxy.server || type || 'Unnamed'));
  const server = proxy.server;
  const port = Number(proxy.port);
  if (!type || !server || !port) return null;
  const common = { name, server, port };
  if (type === 'vmess') return { ...common, type: 'vmess', settings: {
    id: proxy.uuid, aid: proxy.alterId ?? proxy['alter-id'] ?? 0, net: proxy.network || 'tcp',
    type: proxy.type_opts || 'none', host: proxy['ws-opts']?.headers?.Host || proxy['http-opts']?.headers?.Host?.[0] || proxy.servername || '',
    path: proxy['ws-opts']?.path || proxy['http-opts']?.path?.[0] || '', tls: proxy.tls ? 'tls' : '',
    sni: proxy.servername || proxy.sni || '', alpn: ensureArray(proxy.alpn).join(','), scy: proxy.cipher || 'auto',
    service_name: proxy['grpc-opts']?.['grpc-service-name'] || '', packet_encoding: proxy['packet-encoding'] || '',
    global_padding: proxy['global-padding'] === true, authenticated_length: proxy['authenticated-length'] === true,
    fp: proxy['client-fingerprint'] || '', allowInsecure: proxy['skip-cert-verify'] === true,
    v2ray_http_upgrade: proxy['ws-opts']?.['v2ray-http-upgrade'] === true,
    v2ray_http_upgrade_fast_open: proxy['ws-opts']?.['v2ray-http-upgrade-fast-open'] === true
  }};
  if (type === 'vless') return { ...common, type: 'vless', settings: {
    id: proxy.uuid, flow: proxy.flow || '', encryption: proxy.encryption || 'none',
    type: proxy.network || 'tcp', security: proxy['reality-opts'] ? 'reality' : (proxy.tls ? 'tls' : ''),
    path: proxy['ws-opts']?.path || proxy['xhttp-opts']?.path || proxy['http-opts']?.path?.[0] || proxy['h2-opts']?.path || '',
    host: proxy['ws-opts']?.headers?.Host || proxy['xhttp-opts']?.host || proxy['h2-opts']?.host?.[0] || proxy.servername || '',
    sni: proxy.servername || proxy.sni || '', alpn: ensureArray(proxy.alpn).join(','),
    pbk: proxy['reality-opts']?.['public-key'] || '', fp: proxy['client-fingerprint'] || '',
    sid: proxy['reality-opts']?.['short-id'] || '', service_name: proxy['grpc-opts']?.['grpc-service-name'] || '',
    mode: proxy['xhttp-opts']?.mode || '', packet_encoding: proxy['packet-encoding'] || '',
    ech: proxy['ech-opts']?.enable === true, ech_config: proxy['ech-opts']?.config || '',
    ech_query_server_name: proxy['ech-opts']?.['query-server-name'] || '',
    fragment: proxy.fragment === true, record_fragment: proxy['record-fragment'] === true,
    v2ray_http_upgrade: proxy['ws-opts']?.['v2ray-http-upgrade'] === true,
    v2ray_http_upgrade_fast_open: proxy['ws-opts']?.['v2ray-http-upgrade-fast-open'] === true
  }};
  if (type === 'trojan') return { ...common, type: 'trojan', settings: {
    password: proxy.password, type: proxy.network || 'tcp', path: proxy['ws-opts']?.path || proxy['xhttp-opts']?.path || proxy['http-opts']?.path?.[0] || proxy['h2-opts']?.path || '',
    host: proxy['ws-opts']?.headers?.Host || proxy['xhttp-opts']?.host || proxy['http-opts']?.headers?.Host?.[0] || proxy['h2-opts']?.host?.[0] || proxy.servername || '', sni: proxy.sni || proxy.servername || '',
    alpn: ensureArray(proxy.alpn).join(','), allowInsecure: proxy['skip-cert-verify'] === true,
    service_name: proxy['grpc-opts']?.['grpc-service-name'] || '', mode: proxy['xhttp-opts']?.mode || '',
    fp: proxy['client-fingerprint'] || '', ech: proxy['ech-opts']?.enable === true,
    ech_config: proxy['ech-opts']?.config || '', ech_query_server_name: proxy['ech-opts']?.['query-server-name'] || '',
    fragment: proxy.fragment === true, record_fragment: proxy['record-fragment'] === true,
    v2ray_http_upgrade: proxy['ws-opts']?.['v2ray-http-upgrade'] === true,
    v2ray_http_upgrade_fast_open: proxy['ws-opts']?.['v2ray-http-upgrade-fast-open'] === true
  }};
  if (type === 'ss') return { ...common, type: 'ss', settings: {
    method: proxy.cipher, password: proxy.password, plugin: proxy.plugin || null, pluginOpts: proxy['plugin-opts'] || null
  }};
  if (type === 'ssr') return { ...common, type: 'ssr', settings: {
    protocol: proxy.protocol, method: proxy.cipher, obfs: proxy.obfs, password: proxy.password,
    protocolParam: proxy['protocol-param'] || '', obfsParam: proxy['obfs-param'] || ''
  }};
  if (type === 'hysteria') return { ...common, type: 'hysteria', settings: {
    auth: proxy.auth_str || proxy.auth || '', upmbps: proxy.up || proxy.up_mbps || '',
    downmbps: proxy.down || proxy.down_mbps || '', sni: proxy.sni || '', alpn: ensureArray(proxy.alpn).join(','),
    obfs: proxy.obfs || '', insecure: proxy['skip-cert-verify'] === true ? '1' : ''
  }};
  if (type === 'hysteria2' || type === 'hy2') return { ...common, type: 'hysteria2', settings: {
    password: proxy.password || '', auth: proxy.password || '', sni: proxy.sni || '', obfs: proxy.obfs || '',
    obfsParam: proxy['obfs-password'] || '', insecure: proxy['skip-cert-verify'] === true ? '1' : '',
    alpn: ensureArray(proxy.alpn).join(',')
  }};
  if (type === 'tuic') return { ...common, type: 'tuic', settings: {
    uuid: proxy.uuid, password: proxy.password, congestion_control: proxy['congestion-controller'] || proxy.congestion_control || 'bbr',
    udp_relay_mode: proxy['udp-relay-mode'] || proxy.udp_relay_mode || 'native', reduce_rtt: proxy['reduce-rtt'] === true,
    sni: proxy.sni || '', disable_sni: proxy['disable-sni'] === true, alpn: ensureArray(proxy.alpn)
  }};
  if (type === 'socks5' || type === 'socks') return { ...common, type: 'socks5', settings: {
    username: proxy.username || '', password: proxy.password || '', udp: proxy.udp !== false, tls: proxy.tls === true,
    sni: proxy.sni || proxy.servername || ''
  }};
  if (type === 'http') return { ...common, type: 'http', settings: {
    username: proxy.username || '', password: proxy.password || '', tls: proxy.tls === true, sni: proxy.sni || proxy.servername || ''
  }};
  if (type === 'anytls') return { ...common, type: 'anytls', settings: {
    password: proxy.password || '', sni: proxy.sni || proxy.servername || '', alpn: ensureArray(proxy.alpn).join(','),
    insecure: proxy['skip-cert-verify'] === true ? '1' : '', fp: proxy['client-fingerprint'] || '',
    ech: proxy['ech-opts']?.enable === true, ech_config: proxy['ech-opts']?.config || '',
    ech_query_server_name: proxy['ech-opts']?.['query-server-name'] || ''
  }};
  if (type === 'wireguard') return { ...common, type: 'wireguard', settings: {
    private_key: proxy['private-key'] || '',
    public_key: proxy['public-key'] || proxy.peers?.[0]?.['public-key'] || '',
    pre_shared_key: proxy['pre-shared-key'] || proxy.peers?.[0]?.['pre-shared-key'] || '',
    ip: proxy.ip || '',
    ipv6: proxy.ipv6 || '',
    allowed_ips: ensureArray(proxy['allowed-ips'] || proxy.peers?.[0]?.['allowed-ips']),
    reserved: proxy.reserved || proxy.peers?.[0]?.reserved || '',
    persistent_keepalive: proxy['persistent-keepalive'] || '',
    mtu: proxy.mtu || '',
    udp: proxy.udp !== false,
    remote_dns_resolve: proxy['remote-dns-resolve'] === true,
    dns: ensureArray(proxy.dns)
  }};
  if (type === 'ssh') return { ...common, type: 'ssh', settings: {
    user: proxy.user || '',
    password: proxy.password || '',
    private_key: proxy['private-key'] || '',
    private_key_path: proxy['private-key-path'] || '',
    private_key_passphrase: proxy['private-key-passphrase'] || '',
    host_key: ensureArray(proxy['host-key']),
    host_key_algorithms: ensureArray(proxy['host-key-algorithms']),
    client_version: proxy['client-version'] || ''
  }};
  if (type === 'mieru') return { ...common, type: 'mieru', settings: {
    port_range: proxy['port-range'] || '',
    transport: proxy.transport || '',
    username: proxy.username || '',
    password: proxy.password || '',
    multiplexing: proxy.multiplexing || '',
    traffic_pattern: proxy['traffic-pattern'] || ''
  }};
  return null;
}

function isRealSingboxOutbound(outbound) {
  if (!outbound || typeof outbound !== 'object') return false;
  const type = String(outbound.type || '').toLowerCase();
  return !!type && !['block', 'default', 'direct', 'dns', 'selector', 'urltest', 'fallback', 'load-balance'].includes(type);
}

function normalizeSingboxOutbound(outbound) {
  if (!isRealSingboxOutbound(outbound)) return null;
  const type = String(outbound.type || '').toLowerCase();
  const name = decodeNodeName(String(outbound.tag || outbound.server || type || 'Unnamed'));
  const server = outbound.server;
  const port = Number(outbound.server_port || outbound.port);
  const tls = outbound.tls || {};
  const transport = outbound.transport || {};
  if (!server || !port) return null;
  const common = { name, server, port };
  if (type === 'vmess') return { ...common, type: 'vmess', settings: {
    id: outbound.uuid, aid: outbound.alter_id ?? 0, net: transport.type === 'httpupgrade' ? 'ws' : (transport.type || 'tcp'),
    host: transport.headers?.Host || transport.host?.[0] || tls.server_name || '', path: transport.path || '',
    tls: tls.enabled ? 'tls' : '', sni: tls.server_name || '', alpn: ensureArray(tls.alpn).join(''), scy: outbound.security || 'auto',
    service_name: transport.service_name || '', authority: outbound.authority || '', packet_encoding: outbound.packet_encoding || '',
    global_padding: outbound.global_padding === true, authenticated_length: outbound.authenticated_length === true,
    fp: tls.utls?.fingerprint || '', allowInsecure: tls.insecure === true,
    v2ray_http_upgrade: transport.type === 'httpupgrade', v2ray_http_upgrade_fast_open: false
  }};
  if (type === 'vless') return { ...common, type: 'vless', settings: {
    id: outbound.uuid, flow: outbound.flow || '', encryption: outbound.encryption || 'none',
    type: transport.type === 'httpupgrade' ? 'ws' : (transport.type || 'tcp'), security: tls.reality?.enabled ? 'reality' : (tls.enabled ? 'tls' : ''),
    path: transport.path || '', host: transport.headers?.Host || transport.host?.[0] || transport.host || tls.server_name || '',
    sni: tls.server_name || '', alpn: ensureArray(tls.alpn).join(','), pbk: tls.reality?.public_key || '',
    fp: tls.utls?.fingerprint || '', sid: tls.reality?.short_id || '', service_name: transport.service_name || '',
    mode: transport.mode || '', packet_encoding: outbound.packet_encoding || '', ech: tls.ech?.enabled === true,
    ech_config: ensureArray(tls.ech?.config).join('\n') || '', ech_query_server_name: tls.ech?.query_server_name || '',
    fragment: tls.fragment === true, record_fragment: tls.record_fragment === true,
    v2ray_http_upgrade: transport.type === 'httpupgrade', v2ray_http_upgrade_fast_open: false
  }};
  if (type === 'trojan') return { ...common, type: 'trojan', settings: {
    password: outbound.password, type: transport.type === 'httpupgrade' ? 'ws' : (transport.type || 'tcp'), path: transport.path || '',
    host: transport.headers?.Host || transport.host?.[0] || tls.server_name || '', sni: tls.server_name || '',
    alpn: ensureArray(tls.alpn).join(','), allowInsecure: tls.insecure === true, service_name: transport.service_name || '',
    fp: tls.utls?.fingerprint || '', ech: tls.ech?.enabled === true,
    ech_config: ensureArray(tls.ech?.config).join('\n') || '', ech_query_server_name: tls.ech?.query_server_name || '',
    fragment: tls.fragment === true, record_fragment: tls.record_fragment === true,
    v2ray_http_upgrade: transport.type === 'httpupgrade', v2ray_http_upgrade_fast_open: false
  }};
  if (type === 'shadowsocks') return { ...common, type: 'ss', settings: {
    method: outbound.method, password: outbound.password, plugin: outbound.plugin || null, pluginOpts: outbound.plugin_opts || null
  }};
  if (type === 'hysteria') return { ...common, type: 'hysteria', settings: {
    auth: outbound.auth_str || '', upmbps: outbound.up_mbps || '', downmbps: outbound.down_mbps || '',
    sni: tls.server_name || '', alpn: ensureArray(tls.alpn).join(','), obfs: outbound.obfs || '',
    insecure: tls.insecure === true ? '1' : ''
  }};
  if (type === 'hysteria2') return { ...common, type: 'hysteria2', settings: {
    password: outbound.password || '', auth: outbound.password || '', sni: tls.server_name || '',
    obfs: outbound.obfs?.type || '', obfsParam: outbound.obfs?.password || '', insecure: tls.insecure === true ? '1' : '',
    alpn: ensureArray(tls.alpn).join(',')
  }};
  if (type === 'tuic') return { ...common, type: 'tuic', settings: {
    uuid: outbound.uuid, password: outbound.password, congestion_control: outbound.congestion_control || 'bbr',
    udp_relay_mode: outbound.udp_relay_mode || 'native', reduce_rtt: outbound.zero_rtt_handshake === true,
    sni: tls.server_name || '', disable_sni: tls.disable_sni === true, alpn: ensureArray(tls.alpn)
  }};
  if (type === 'socks') return { ...common, type: 'socks5', settings: {
    username: outbound.username || '', password: outbound.password || '', udp: outbound.udp_over_tcp !== true,
    tls: tls.enabled === true, sni: tls.server_name || ''
  }};
  if (type === 'http') return { ...common, type: 'http', settings: {
    username: outbound.username || '', password: outbound.password || '', tls: tls.enabled === true, sni: tls.server_name || ''
  }};
  if (type === 'anytls') return { ...common, type: 'anytls', settings: {
    password: outbound.password || '', sni: tls.server_name || '', alpn: ensureArray(tls.alpn).join(','),
    insecure: tls.insecure === true ? '1' : '', fp: tls.utls?.fingerprint || '',
    ech: tls.ech?.enabled === true, ech_config: ensureArray(tls.ech?.config).join('\n') || '',
    ech_query_server_name: tls.ech?.query_server_name || ''
  }};
  if (type === 'wireguard') return { ...common, type: 'wireguard', settings: {
    private_key: outbound.private_key || '',
    public_key: outbound.peer_public_key || outbound.peers?.[0]?.public_key || '',
    pre_shared_key: outbound.pre_shared_key || '',
    ip: ensureArray(outbound.local_address)[0] || '',
    ipv6: ensureArray(outbound.local_address)[1] || '',
    allowed_ips: ensureArray(outbound.peers?.[0]?.allowed_ips),
    reserved: outbound.reserved || outbound.peers?.[0]?.reserved || '',
    mtu: outbound.mtu || '',
    udp: !Array.isArray(outbound.network) || outbound.network.includes('udp')
  }};
  if (type === 'ssh') return { ...common, type: 'ssh', settings: {
    user: outbound.user || '',
    password: outbound.password || '',
    private_key: outbound.private_key || '',
    private_key_path: outbound.private_key_path || '',
    private_key_passphrase: outbound.private_key_passphrase || '',
    host_key: ensureArray(outbound.host_key),
    host_key_algorithms: ensureArray(outbound.host_key_algorithms),
    client_version: outbound.client_version || ''
  }};
  return null;
}

export default class ParserV2 {
  static isRemoteSubscriptionUrl(value) {
    try {
      const url = new URL(value);
      return url.protocol === 'http:' || url.protocol === 'https:';
    } catch {
      return false;
    }
  }

  static isSubscriptionUrl(value) {
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return false;
    if (!this.isRemoteSubscriptionUrl(value) || isNodeScheme(value)) return false;
    try {
      const url = new URL(value);
      if (url.username || url.password) return false;
      return true;
    } catch {
      return false;
    }
  }

  static tryBase64Decode(content) {
    try {
      if (!/^[A-Za-z0-9+/=\r\n]+$/.test(content.trim())) return content;
      const decoded = atob(content.replace(/\s+/g, ''));
      return NODE_SCHEMES.some(protocol => decoded.includes(protocol)) ? decoded : content;
    } catch {
      return content;
    }
  }

  static detectContentType(content) {
    const trimmed = content.trim();
    if (!trimmed) return 'plain';
    if ((trimmed.startsWith('{') || trimmed.startsWith('[')) && trimmed.includes('"outbounds"')) return 'singbox-json';
    if (/^\s*proxies\s*:/m.test(content)) return 'clash-yaml';
    return 'plain';
  }

  static parseClashConfig(content) {
    const lines = content.split(/\r?\n/);
    const proxiesIndex = lines.findIndex(line => line.trim() === 'proxies:');
    if (proxiesIndex === -1) return [];
    const sectionIndent = getIndent(lines[proxiesIndex]);
    const proxyLines = [];
    for (let i = proxiesIndex + 1; i < lines.length; i += 1) {
      const line = lines[i];
      if (isCommentOrEmpty(line)) {
        proxyLines.push(line);
        continue;
      }
      const indent = getIndent(line);
      if (indent <= sectionIndent && !line.trim().startsWith('- ')) break;
      proxyLines.push(line);
    }
    const [proxies] = parseYamlList(proxyLines, 0, sectionIndent + 2);
    return Array.isArray(proxies) ? proxies.map(proxy => normalizeClashProxy(proxy)).filter(Boolean) : [];
  }

  static parseSingboxConfig(content) {
    try {
      const parsed = JSON.parse(content);
      const outbounds = Array.isArray(parsed?.outbounds) ? parsed.outbounds : [];
      return outbounds.map(outbound => normalizeSingboxOutbound(outbound)).filter(Boolean);
    } catch (error) {
      console.error('Parse sing-box config error:', error);
      return [];
    }
  }

  static async parse(url, env, context = {}) {
    const state = { depth: context.depth || 0, visited: context.visited || new Set() };
    try {
      if (!url || typeof url !== 'string') throw new Error('Invalid URL format');
      if (state.depth > MAX_RECURSION_DEPTH) throw new Error('Maximum subscription depth exceeded');

      if (url.startsWith('http://inner.nodes.secret/id-')) {
        const collectionId = url.replace('http://inner.nodes.secret/id-', '');
        const collections = await env.NODE_STORE.get(CONFIG.COLLECTIONS_KEY);
        if (!collections) throw new Error('No collections found');
        const collection = JSON.parse(collections).find(item => item.id === collectionId);
        if (!collection) throw new Error('Collection not found');
        const nodesData = await env.NODE_STORE.get(CONFIG.KV_KEY);
        if (!nodesData) throw new Error('No nodes found');
        const nodes = JSON.parse(nodesData).filter(node => collection.nodeIds.includes(node.id));
        let processedNodes = [];
        for (const node of nodes) {
          if (this.isSubscriptionUrl(node.url)) {
            processedNodes = processedNodes.concat(await this.parse(node.url, env, { depth: state.depth + 1, visited: state.visited }));
          } else {
            const parsedNode = this.parseLine(node.url);
            if (parsedNode) processedNodes.push(parsedNode);
          }
        }
        return processedNodes;
      }

      if (!this.isSubscriptionUrl(url)) {
        const singleNode = this.parseLine(url);
        return singleNode ? [singleNode] : [];
      }

      if (state.visited.has(url)) return [];
      state.visited.add(url);
      const response = await fetch(url);
      if (!response.ok) throw new Error(`Failed to fetch subscription: ${response.status}`);
      const contentLength = Number(response.headers.get('content-length') || 0);
      if (contentLength > MAX_SUBSCRIPTION_BYTES) throw new Error('Subscription content too large');
      const content = await response.text();
      if (content.length > MAX_SUBSCRIPTION_BYTES) throw new Error('Subscription content too large');
      return await this.parseContent(content, env, { depth: state.depth + 1, visited: state.visited });
    } catch (error) {
      console.error('Parser error:', error);
      return [];
    }
  }

  static async parseContent(content, env, context = {}) {
    try {
      if (!content) return [];
      const decodedContent = this.tryBase64Decode(content);
      const contentType = this.detectContentType(decodedContent);
      if (contentType === 'clash-yaml') return this.parseClashConfig(decodedContent);
      if (contentType === 'singbox-json') return this.parseSingboxConfig(decodedContent);
      const lines = decodedContent.split(/\r?\n/).filter(line => line.trim());
      let nodes = [];
      for (const line of lines) {
        const value = line.trim();
        if (this.isSubscriptionUrl(value)) nodes = nodes.concat(await this.parse(value, env, context));
        else {
          const node = this.parseLine(value);
          if (node) nodes.push(node);
        }
      }
      return nodes;
    } catch (error) {
      console.error('Parse error:', error);
      return [];
    }
  }

  static parseLine(line) {
    if (!line) return null;
    try {
      const lower = line.toLowerCase();
      if (lower.startsWith('vmess://')) return this.parseVmess(line);
      if (lower.startsWith('vless://')) return this.parseVless(line);
      if (lower.startsWith('trojan://')) return this.parseTrojan(line);
      if (lower.startsWith('ss://')) return this.parseSS(line);
      if (lower.startsWith('ssr://')) return this.parseSSR(line);
      if (lower.startsWith('hysteria://')) return this.parseHysteria(line);
      if (lower.startsWith('hysteria2://') || lower.startsWith('hy2://')) return this.parseHysteria2(line);
      if (lower.startsWith('tuic://')) return this.parseTuic(line);
      if (lower.startsWith('anytls://')) return this.parseAnytls(line);
      if (lower.startsWith('socks5://') || lower.startsWith('socks://')) return this.parseSocks(line);
      if (lower.startsWith('http://') || lower.startsWith('https://')) return this.parseHttp(line);
      return null;
    } catch (error) {
      console.error('Parse line error:', error);
      return null;
    }
  }

  static parseVmess(line) {
    try {
      const safeContent = line.slice(8).replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
      const padded = safeContent + '='.repeat((4 - safeContent.length % 4) % 4);
      const config = JSON.parse(atob(padded));
      return { type: 'vmess', name: decodeNodeName(config.ps || 'Unnamed'), server: config.add, port: parseInt(config.port), settings: {
        id: config.id, aid: parseInt(config.aid), scy: config.scy || 'auto', net: config.net, type: config.type, host: config.host, path: config.path,
        tls: config.tls, sni: config.sni, alpn: config.alpn, service_name: config.serviceName || '', authority: config.authority || '',
        packet_encoding: config.packetEncoding || '', global_padding: config.globalPadding === true, authenticated_length: config.authenticatedLength === true,
        allowInsecure: config.allowInsecure === true || config.allowInsecure === '1', fp: config.fp || config.fingerprint || ''
      }};
    } catch (error) { console.error('Parse VMess error:', error); return null; }
  }

  static parseVless(line) {
    try {
      const url = new URL(line);
      const params = new URLSearchParams(url.search);
      return { type: 'vless', name: decodeNodeName(url.hash.slice(1)), server: url.hostname, port: parseInt(url.port), settings: {
        id: url.username, flow: params.get('flow') || '', encryption: params.get('encryption') || 'none',
        type: params.get('type') || 'tcp', security: params.get('security') || '', path: params.get('path') || '',
        host: params.get('host') || '', sni: params.get('sni') || '', alpn: params.get('alpn') || '',
        pbk: params.get('pbk') || '', fp: params.get('fp') || '', sid: params.get('sid') || '', spx: params.get('spx') || '',
        service_name: params.get('serviceName') || '', authority: params.get('authority') || '', mode: params.get('mode') || '',
        headerType: params.get('headerType') || '', seed: params.get('seed') || '', packet_encoding: params.get('packetEncoding') || '',
        ech: params.get('ech') || '', ech_config: params.get('echConfig') || '', ech_query_server_name: params.get('echQueryServerName') || '',
        pqv: params.get('pqv') || '', allowInsecure: params.get('allowInsecure') || params.get('insecure') || '',
        fragment: params.get('fragment') || '', record_fragment: params.get('recordFragment') || ''
      }};
    } catch (error) { console.error('Parse VLESS error:', error); return null; }
  }

  static parseTrojan(line) {
    try {
      const url = new URL(line);
      const params = new URLSearchParams(url.search);
      const settings = {
        type: params.get('type') || 'tcp',
        security: params.get('security') || '',
        path: params.get('path') || '',
        host: params.get('host') || '',
        sni: params.get('sni') || '',
        alpn: params.get('alpn') || '',
        service_name: params.get('serviceName') || '',
        authority: params.get('authority') || '',
        mode: params.get('mode') || '',
        headerType: params.get('headerType') || '',
        fp: params.get('fp') || '',
        ech: params.get('ech') || '',
        ech_config: params.get('echConfig') || '',
        ech_query_server_name: params.get('echQueryServerName') || '',
        fragment: params.get('fragment') || '',
        record_fragment: params.get('recordFragment') || '',
        v2ray_http_upgrade: params.get('v2rayHttpUpgrade') || '',
        v2ray_http_upgrade_fast_open: params.get('v2rayHttpUpgradeFastOpen') || ''
      };
      settings.allowInsecure = params.get('allowInsecure') === '1' || params.get('insecure') === '1';
      settings.password = url.username;
      return { type: 'trojan', name: decodeNodeName(url.hash.slice(1)) || decodeNodeName(params.get('remarks') || ''), server: url.hostname, port: parseInt(url.port), settings };
    } catch (error) { console.error('Parse Trojan error:', error); return null; }
  }

  static parseSS(line) {
    try {
      const url = new URL(line);
      const parts = base64DecodeSmart(url.username).split(':');
      if (parts.length < 2) return null;
      const pluginOpts = {};
      for (const [key, value] of url.searchParams.entries()) if (key.startsWith('plugin_')) pluginOpts[key.slice(7)] = value;
      return { type: 'ss', name: url.hash ? decodeURIComponent(url.hash.slice(1)) : 'Unnamed', server: url.hostname, port: parseInt(url.port), settings: {
        method: parts[0], password: parts.slice(1).join(':'), plugin: url.searchParams.get('plugin') || null,
        pluginOpts: Object.keys(pluginOpts).length ? pluginOpts : null
      }};
    } catch (error) { console.error('Error parsing SS:', error); return null; }
  }

  static parseSSR(line) {
    try {
      let base64 = line.slice(6).replace(/-/g, '+').replace(/_/g, '/');
      while (base64.length % 4 !== 0) base64 += '=';
      const decoded = atob(base64);
      const [baseConfig, query] = decoded.split('/?');
      const [server, port, protocol, method, obfs, password] = baseConfig.split(':');
      const params = new URLSearchParams(query);
      return { type: 'ssr', name: params.get('remarks') ? base64DecodeSmart(params.get('remarks')) : '', server, port: parseInt(port), settings: {
        protocol, method, obfs, password: atob(password),
        protocolParam: params.get('protoparam') ? atob(params.get('protoparam')) : '',
        obfsParam: params.get('obfsparam') ? atob(params.get('obfsparam')) : ''
      }};
    } catch (error) { console.error('Parse ShadowsocksR error:', error); return null; }
  }

  static parseHysteria(line) {
    try {
      const url = new URL(line);
      const params = new URLSearchParams(url.search);
      const settings = {};
      ['alpn', 'auth', 'auth_str', 'protocol', 'obfs', 'obfsParam', 'sni', 'peer', 'delay', 'insecure', 'password', 'username']
        .forEach(key => { if (params.get(key) !== null) settings[key] = params.get(key); });
      if (params.get('up')) settings.up = params.get('up');
      if (params.get('down')) settings.down = params.get('down');
      if (params.get('upmbps')) settings.upmbps = params.get('upmbps');
      if (params.get('downmbps')) settings.downmbps = params.get('downmbps');
      if (!settings.auth && url.username) settings.auth = url.username;
      return { type: 'hysteria', name: decodeNodeName(url.hash.slice(1)) || decodeNodeName(params.get('remarks') || ''), server: url.hostname, port: parseInt(url.port), settings };
    } catch (error) { console.error('Parse Hysteria error:', error); return null; }
  }

  static parseHysteria2(line) {
    try {
      const url = new URL(line.replace(/^hy2:\/\//i, 'hysteria2://'));
      const params = new URLSearchParams(url.search);
      const settings = {};
      ['sni', 'obfs', 'insecure', 'alpn', 'peer', 'delay', 'password', 'username']
        .forEach(key => { if (params.get(key) !== null) settings[key] = params.get(key); });
      if (params.get('obfs-password') !== null) settings.obfsParam = params.get('obfs-password');
      if (!settings.auth && url.username) settings.auth = url.username;
      return { type: 'hysteria2', name: decodeNodeName(url.hash.slice(1)) || decodeNodeName(params.get('remarks') || ''), server: url.hostname, port: parseInt(url.port), settings };
    } catch (error) { console.error('Parse Hysteria2 error:', error); return null; }
  }

  static parseTuic(line) {
    try {
      const url = new URL(line);
      const params = new URLSearchParams(url.search);
      return { type: 'tuic', name: decodeNodeName(url.hash.slice(1)), server: url.hostname, port: parseInt(url.port), settings: {
        uuid: url.username, password: url.password, congestion_control: params.get('congestion_control') || 'bbr',
        udp_relay_mode: params.get('udp_relay_mode') || 'native', alpn: (params.get('alpn') || '').split(',').filter(Boolean),
        reduce_rtt: params.get('reduce_rtt') === '1', sni: params.get('sni') || '', disable_sni: params.get('disable_sni') === '1'
      }};
    } catch (error) { console.error('Parse TUIC error:', error); return null; }
  }

  static parseAnytls(line) {
    try {
      const url = new URL(line);
      const params = new URLSearchParams(url.search);
      return { type: 'anytls', name: decodeNodeName(url.hash.slice(1)), server: url.hostname, port: parseInt(url.port), settings: {
        password: url.username || url.password || '', sni: params.get('sni') || params.get('servername') || '',
        alpn: params.get('alpn') || '', insecure: params.get('insecure') || params.get('allowInsecure') || '',
        fp: params.get('fp') || '', ech: params.get('ech') || '', ech_config: params.get('echConfig') || '',
        ech_query_server_name: params.get('echQueryServerName') || ''
      }};
    } catch (error) { console.error('Parse AnyTLS error:', error); return null; }
  }

  static parseSocks(line) {
    try {
      const url = new URL(line);
      return { type: 'socks5', name: decodeNodeName(url.hash.slice(1)) || decodeNodeName(url.hostname), server: url.hostname, port: parseInt(url.port), settings: {
        username: url.username || '', password: url.password || '', udp: true, tls: false, sni: ''
      }};
    } catch (error) { console.error('Parse SOCKS error:', error); return null; }
  }

  static parseHttp(line) {
    try {
      const url = new URL(line);
      return { type: 'http', name: decodeNodeName(url.hash.slice(1)) || decodeNodeName(url.hostname), server: url.hostname, port: parseInt(url.port || (url.protocol === 'https:' ? '443' : '80')), settings: {
        username: url.username || '', password: url.password || '', tls: url.protocol === 'https:', sni: url.hostname
      }};
    } catch (error) { console.error('Parse HTTP proxy error:', error); return null; }
  }
}
