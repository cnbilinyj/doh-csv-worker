const DEFAULT_TTL = 300;
const TYPE = { A:1, NS:2, CNAME:5, SOA:6, PTR:12, MX:15, TXT:16, AAAA:28, SRV:33, CAA:257 };
const TYPE_NAME = Object.fromEntries(Object.entries(TYPE).map(([k,v]) => [v,k]));
const CLASS_IN = 1;

// base64url -> bytes
function b64uToBytes(b64u){
  const b64 = b64u.replace(/-/g,"+").replace(/_/g,"/");
  const pad = b64.length % 4 ? (4 - (b64.length % 4)) : 0;
  const s = b64 + "=".repeat(pad);
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);
  return bytes;
}

// bytes -> base64url
function bytesToB64u(bytes){
  let bin="";
  for (let i=0;i<bytes.length;i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
}

function concatBytes(parts){
  let len=0; for (const p of parts) len+=p.length;
  const out=new Uint8Array(len); let off=0;
  for (const p of parts){ out.set(p,off); off+=p.length; }
  return out;
}

function readU16(b,o){ return (b[o]<<8)|b[o+1]; }
function writeU16(o,off,v){ o[off]=(v>>8)&0xff; o[off+1]=v&0xff; }
function writeU32(o,off,v){ o[off]=(v>>>24)&0xff; o[off+1]=(v>>>16)&0xff; o[off+2]=(v>>>8)&0xff; o[off+3]=v&0xff; }

// 把 "www.example.com." 编码成 DNS name 格式
function encodeName(name){
  if (!name) name=".";
  if (name === ".") return new Uint8Array([0]);
  const labels = name.replace(/\.$/,"").split(".");
  const parts=[];
  const enc=new TextEncoder();
  for (const label of labels){
    const b=enc.encode(label);
    if (b.length>63) throw new Error("label too long");
    parts.push(new Uint8Array([b.length]), b);
  }
  parts.push(new Uint8Array([0]));
  return concatBytes(parts);
}

// 从 DNS 报文里解码域名（支持压缩指针）
function decodeName(msg, off){
  const labels=[]; let jumped=false; let nextOff=off; let seen=0;
  while (true){
    if (off>=msg.length) throw new Error("name out of bounds");
    const len=msg[off];
    if ((len & 0xC0) === 0xC0){
      if (off+1>=msg.length) throw new Error("bad pointer");
      const ptr=((len & 0x3F)<<8)|msg[off+1];
      if (!jumped) nextOff=off+2;
      jumped=true; off=ptr;
      if (++seen>20) throw new Error("too many jumps");
      continue;
    }
    if (len===0){ if (!jumped) nextOff=off+1; break; }
    off++;
    if (off+len>msg.length) throw new Error("label out of bounds");
    labels.push(new TextDecoder().decode(msg.slice(off, off+len)));
    off+=len;
    if (++seen>128) throw new Error("name too long");
  }
  const name = labels.length ? labels.join(".")+"." : ".";
  return { name, nextOff };
}

// 解析 DNS 查询报文的 question
function parseDnsQuery(msg){
  if (msg.length<12) throw new Error("too short");
  const id=readU16(msg,0);
  const flags=readU16(msg,2);
  const qd=readU16(msg,4);
  if (qd<1) throw new Error("no question");
  let off=12;
  const q=decodeName(msg,off); off=q.nextOff;
  if (off+4>msg.length) throw new Error("question truncated");
  const qtype=readU16(msg,off);
  const qclass=readU16(msg,off+2);
  return { id, flags, qname:q.name.toLowerCase(), qtype, qclass };
}

// IPv4 字符串转 4 字节
function ipv4ToBytes(ip){
  const parts=ip.trim().split(".");
  if (parts.length!==4) throw new Error("bad ipv4");
  return new Uint8Array(parts.map(x=>parseInt(x,10)));
}

// 简单 IPv6 字符串转 16 字节（支持 :: 压缩，不支持内嵌 IPv4）
function ipv6ToBytes(ip){
  const s=ip.trim();
  if (s.includes(".")) throw new Error("ipv4-embedded ipv6 not supported");
  const [left,right]=s.split("::");
  const lp=left?left.split(":"):[];
  const rp=right?right.split(":"):[];
  const missing=8-(lp.length+rp.length);
  if (missing<0) throw new Error("bad ipv6");
  const groups=[...lp,...Array(missing).fill("0"),...rp].map(x=>parseInt(x||"0",16));
  const out=new Uint8Array(16);
  for (let i=0;i<8;i++){ out[i*2]=(groups[i]>>8)&0xff; out[i*2+1]=groups[i]&0xff; }
  return out;
}

// TXT 的 rdata：多个 character-string
function txtStringsToRdata(strings){
  const enc=new TextEncoder();
  const parts=[];
  for (const s of strings){
    const b=enc.encode(String(s));
    for (let i=0;i<b.length;i+=255){
      const chunk=b.slice(i,i+255);
      parts.push(new Uint8Array([chunk.length]), chunk);
    }
    if (b.length===0) parts.push(new Uint8Array([0]));
  }
  return concatBytes(parts);
}

// 按 RR 类型编码 rdata
function encodeRdata(rr){
  const type=rr.type;
  const data=rr.data;

  if (type==="A") return ipv4ToBytes(data);
  if (type==="AAAA") return ipv6ToBytes(data);
  if (type==="CNAME" || type==="NS" || type==="PTR") return encodeName(String(data));

  if (type==="TXT"){
    let arr;
    if (Array.isArray(data)) arr=data;
    else {
      const s=String(data);
      if (s.trim().startsWith("[")) { try { arr=JSON.parse(s); } catch { arr=[s]; } }
      else arr=[s];
    }
    return txtStringsToRdata(arr.map(x=>String(x)));
  }

  if (type==="MX"){
    const m=String(data).trim().split(/\s+/);
    const pref=parseInt(m[0],10);
    const exchange=m.slice(1).join(" ");
    const out=new Uint8Array(2 + encodeName(exchange).length);
    writeU16(out,0,pref);
    out.set(encodeName(exchange),2);
    return out;
  }

  if (type==="SRV"){
    const m=String(data).trim().split(/\s+/);
    const priority=parseInt(m[0],10);
    const weight=parseInt(m[1],10);
    const port=parseInt(m[2],10);
    const target=m.slice(3).join(" ");
    const t=encodeName(target);
    const out=new Uint8Array(6+t.length);
    writeU16(out,0,priority);
    writeU16(out,2,weight);
    writeU16(out,4,port);
    out.set(t,6);
    return out;
  }

  if (type==="CAA"){
    const s=String(data).trim();
    const m=s.match(/^(\d+)\s+([a-zA-Z0-9]+)\s+([\s\S]+)$/);
    if (!m) throw new Error("bad CAA data");
    const flags=parseInt(m[1],10);
    const tag=m[2];
    let value=m[3].trim();
    if (value.startsWith('"') && value.endsWith('"')) value=value.slice(1,-1);
    const enc=new TextEncoder();
    const tb=enc.encode(tag);
    const vb=enc.encode(value);
    const out=new Uint8Array(1+1+tb.length+vb.length);
    out[0]=flags; out[1]=tb.length;
    out.set(tb,2); out.set(vb,2+tb.length);
    return out;
  }

  if (type==="SOA"){
    const m=String(data).trim().split(/\s+/);
    if (m.length < 7) throw new Error("bad SOA data");
    const mname=m[0];
    const rname=m[1];
    const nums=m.slice(2,7).map(x=>parseInt(x,10));
    const mn=encodeName(mname), rn=encodeName(rname);
    const out=new Uint8Array(mn.length+rn.length+20);
    let off=0;
    out.set(mn,off); off+=mn.length;
    out.set(rn,off); off+=rn.length;
    writeU32(out,off,nums[0]); off+=4;
    writeU32(out,off,nums[1]); off+=4;
    writeU32(out,off,nums[2]); off+=4;
    writeU32(out,off,nums[3]); off+=4;
    writeU32(out,off,nums[4]); off+=4;
    return out;
  }

  throw new Error(`Unsupported RR type: ${type}`);
}

// 解析一行 CSV（支持引号包裹和 "" 转义）
function parseCsvLine(line){
  const out=[]; let cur=""; let inQ=false;
  for (let i=0;i<line.length;i++){
    const ch=line[i];
    if (inQ){
      if (ch==='"'){
        if (i+1<line.length && line[i+1]==='"'){ cur+='"'; i++; }
        else inQ=false;
      } else cur+=ch;
    } else {
      if (ch==='"') inQ=true;
      else if (ch===','){ out.push(cur); cur=""; }
      else cur+=ch;
    }
  }
  out.push(cur);
  return out.map(s=>s.trim());
}

// 把 CSV 文本转成配置对象
function csvToConfig(csvText){
  const lines = csvText.replace(/^\uFEFF/, "").split(/\r?\n/).filter(l => l.trim().length);
  if (!lines.length) return { rules: {} };

  const header = parseCsvLine(lines[0]).map(h => h.toLowerCase());
  const idx = {
    name: header.indexOf("name"),
    type: header.indexOf("type"),
    ttl: header.indexOf("ttl"),
    data: header.indexOf("data"),
    rcode: header.indexOf("rcode"),
  };
  if (idx.name < 0) throw new Error("CSV missing header: name");

  const rules = {};
  for (let i=1;i<lines.length;i++){
    const cols = parseCsvLine(lines[i]);
    const name = (cols[idx.name] || "").toLowerCase();
    if (!name) continue;

    const type = idx.type >= 0 ? (cols[idx.type] || "").toUpperCase() : "";
    const ttl = idx.ttl >= 0 ? parseInt(cols[idx.ttl] || "", 10) : NaN;
    const data = idx.data >= 0 ? (cols[idx.data] ?? "") : "";
    const rcode = idx.rcode >= 0 ? (cols[idx.rcode] || "").toUpperCase() : "";

    if (!rules[name]) rules[name] = { records: {} };

    if (rcode === "ROUTE") {
      rules[name].route = { proto: type || "DOH", target: data };
      continue;
    }

    if (rcode) {
      rules[name].rcode = rcode;
      continue;
    }

    if (!type || !TYPE[type]) continue;

    const rr = { data };
    if (!Number.isNaN(ttl)) rr.ttl = ttl;
    (rules[name].records[type] ||= []).push(rr);
  }
  return { rules };
}

// 从 CONFIG_URL 拉取 CSV 并缓存
let cachedConfig = null;
let cachedAt = 0;
async function loadConfig(env){
  const ttl = parseInt(env.CONFIG_CACHE_TTL_SECONDS || "60", 10);
  const now = Date.now();
  if (cachedConfig && (now - cachedAt) < ttl*1000) return cachedConfig;

  if (env.CONFIG_URL) {
    try {
      const res = await fetch(env.CONFIG_URL, { cf: { cacheTtl: ttl } });
      if (res.ok) {
        const text = await res.text();
        cachedConfig = csvToConfig(text);
        cachedAt = now;
        return cachedConfig;
      }
    } catch (e) {}
  }

  if (env.CONFIG_CSV) {
    try {
      cachedConfig = csvToConfig(env.CONFIG_CSV);
      cachedAt = now;
      return cachedConfig;
    } catch (e) {}
  }

  cachedConfig = { rules: {} };
  cachedAt = now;
  return cachedConfig;
}

// 精确匹配 -> 通配匹配
function findRule(cfg, qname){
  if (!cfg || !cfg.rules) return null;
  if (cfg.rules[qname]) return cfg.rules[qname];
  const labels = qname.split(".");
  for (let i=1;i<labels.length-1;i++){
    const wild = "*." + labels.slice(i).join(".");
    if (cfg.rules[wild]) return cfg.rules[wild];
  }
  return null;
}

// 构造本地 DNS 响应（自定义记录 / rcode）
function buildLocalResponse(queryMsg, cfg){
  const q = parseDnsQuery(queryMsg);
  const header = new Uint8Array(12);
  writeU16(header, 0, q.id);

  const rd = (q.flags & 0x0100) ? 0x0100 : 0;
  let rcode = 0;
  let answers = [];
  let authority = [];

  const question = concatBytes([
    encodeName(q.qname),
    new Uint8Array([ (q.qtype>>8)&0xff, q.qtype&0xff, (q.qclass>>8)&0xff, q.qclass&0xff ])
  ]);

  const rule = findRule(cfg, q.qname);
  const defaultSoa = cfg?.defaultSoa || {
    mname: "ns1.invalid.", rname: "hostmaster.invalid.",
    serial: 1, refresh: 7200, retry: 3600, expire: 1209600, minimum: 300
  };

  if (!rule) {
    rcode = 3; // NXDOMAIN
    authority.push({ name: q.qname, type: "SOA", ttl: 300, data: soaToString(defaultSoa) });
  } else if (rule.rcode) {
    const rc = String(rule.rcode).toUpperCase();
    rcode = rc === "NXDOMAIN" ? 3 : rc === "SERVFAIL" ? 2 : rc === "REFUSED" ? 5 : 0;
    if (rcode === 3) authority.push({ name: q.qname, type: "SOA", ttl: 300, data: soaToString(defaultSoa) });
  } else {
    const rrset = rule.records?.[TYPE_NAME[q.qtype]];
    if (rrset && rrset.length) {
      answers = rrset.map(rr => ({ name: q.qname, type: TYPE_NAME[q.qtype], ttl: rr.ttl ?? DEFAULT_TTL, data: rr.data }));
    } else {
      rcode = 0;
      authority.push({ name: q.qname, type: "SOA", ttl: 300, data: soaToString(defaultSoa) });
    }
  }

  const answerBytes = [];
  for (const rr of answers) {
    const rdata = encodeRdata(rr);
    const rdlen = rdata.length;
    answerBytes.push(concatBytes([
      encodeName(rr.name),
      new Uint8Array([ (TYPE[rr.type]>>8)&0xff, TYPE[rr.type]&0xff, (CLASS_IN>>8)&0xff, CLASS_IN&0xff ]),
      new Uint8Array([ (rr.ttl>>>24)&0xff, (rr.ttl>>>16)&0xff, (rr.ttl>>>8)&0xff, rr.ttl&0xff ]),
      new Uint8Array([ (rdlen>>8)&0xff, rdlen&0xff ]),
      rdata
    ]));
  }

  const authorityBytes = [];
  for (const rr of authority) {
    const rdata = encodeRdata(rr);
    const rdlen = rdata.length;
    authorityBytes.push(concatBytes([
      encodeName(rr.name),
      new Uint8Array([ (TYPE[rr.type]>>8)&0xff, TYPE[rr.type]&0xff, (CLASS_IN>>8)&0xff, CLASS_IN&0xff ]),
      new Uint8Array([ (rr.ttl>>>24)&0xff, (rr.ttl>>>16)&0xff, (rr.ttl>>>8)&0xff, rr.ttl&0xff ]),
      new Uint8Array([ (rdlen>>8)&0xff, rdlen&0xff ]),
      rdata
    ]));
  }

  const flags = 0x8000 | 0x0400 | rd | 0x0080 | (rcode & 0xF);
  writeU16(header, 2, flags);
  writeU16(header, 4, 1);
  writeU16(header, 6, answers.length);
  writeU16(header, 8, authority.length);
  writeU16(header, 10, 0);

  return concatBytes([header, question, ...answerBytes, ...authorityBytes]);
}

function soaToString(soa){
  return `${soa.mname} ${soa.rname} ${soa.serial} ${soa.refresh} ${soa.retry} ${soa.expire} ${soa.minimum}`;
}

// 通过 DoH 上游解析
async function resolveViaDoh(queryBytes, dohUrl){
  const res = await fetch(dohUrl, {
    method: "POST",
    headers: { "content-type": "application/dns-message", "accept": "application/dns-message" },
    body: queryBytes
  });
  if (!res.ok) throw new Error("DoH upstream error: " + res.status);
  return new Uint8Array(await res.arrayBuffer());
}

// 通过 UDP DNS 上游解析（依赖 Worker socket 能力）
async function resolveViaUdp(queryBytes, target){
  const [host, portStr] = target.split(":");
  const port = parseInt(portStr || "53", 10);

  const { connect } = await import("cloudflare:sockets");
  const socket = connect(`${host}:${port}`, { type: "udp" });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();

  try {
    await writer.write(queryBytes);
    const { value, done } = await reader.read();
    if (done || !value) throw new Error("udp no response");
    return new Uint8Array(value);
  } finally {
    try { writer.close(); } catch {}
    try { reader.cancel(); } catch {}
    try { socket.close(); } catch {}
  }
}

async function routeResolve(queryBytes, route){
  const proto = (route.proto || "DOH").toUpperCase();
  const target = route.target;
  if (!target) throw new Error("route target empty");

  if (proto === "DOH") return await resolveViaDoh(queryBytes, target);
  if (proto === "UDP") return await resolveViaUdp(queryBytes, target);
  throw new Error("unknown route proto: " + proto);
}

// WebUI 用的 JSON 测试接口（只展示本地规则，不真正转发上游）
function jsonResolve(cfg, url){
  const name=(url.searchParams.get("name")||"").toLowerCase();
  const type=(url.searchParams.get("type")||"A").toUpperCase();
  const resp={ Status:0, TC:false, RD:true, RA:true, AD:false, CD:false,
    Question:[{name, type: TYPE[type]||1}], Answer: [] };

  const rule=findRule(cfg,name);
  if (!rule){ resp.Status=3; return resp; }
  if (rule.rcode){
    const rc=String(rule.rcode).toUpperCase();
    resp.Status = rc==="NXDOMAIN"?3: rc==="SERVFAIL"?2: rc==="REFUSED"?5:0;
    return resp;
  }
  if (rule.route){
    resp.Answer.push({ name, type: 16, TTL: 0, data: JSON.stringify({ routed: rule.route }) });
    return resp;
  }
  const rrset=rule.records?.[type];
  if (!rrset) return resp;

  for (const rr of rrset){
    const ttl=rr.ttl ?? DEFAULT_TTL;
    const data=rr.data;
    if (type==="TXT"){
      let arr;
      const s=String(data);
      if (s.trim().startsWith("[")) { try { arr=JSON.parse(s); } catch { arr=[s]; } }
      else arr=[s];
      resp.Answer.push({ name, type: TYPE.TXT, TTL: ttl, data: JSON.stringify(arr) });
    } else if (type==="SRV" || type==="MX" || type==="CAA" || type==="SOA") {
      resp.Answer.push({ name, type: TYPE[type], TTL: ttl, data: JSON.stringify(data) });
    } else {
      resp.Answer.push({ name, type: TYPE[type], TTL: ttl, data: String(data) });
    }
  }
  return resp;
}

// 简单 WebUI 页面
function htmlPage(cfg, env){
  const configUrl = env.CONFIG_URL || "";
  const rulesCount = Object.keys(cfg?.rules || {}).length;
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DoH CSV Admin</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:24px;}
    textarea{width:100%;height:260px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;}
    input{width:100%;padding:8px;margin:6px 0;}
    button{padding:8px 12px;}
    pre{background:#f6f8fa;padding:12px;overflow:auto;}
    .row{display:flex;gap:8px;flex-wrap:wrap;}
    .card{border:1px solid #ddd;border-radius:8px;padding:12px;margin:12px 0;}
    code{background:#eee;padding:2px 4px;border-radius:4px;}
  </style>
</head>
<body>
  <h2>DoH CSV Admin</h2>
  <div class="card">
    <div><b>DoH endpoint:</b> <code>/dns-query</code></div>
    <div><b>Config URL:</b> <code>${configUrl || "(none)"}</code></div>
    <div><b>Rules loaded:</b> ${rulesCount}</div>
    <div><b>Default upstream:</b> Cloudflare DoH</div>
  </div>

  <div class="card">
    <h3>Test lookup (local rules only)</h3>
    <div class="row">
      <input id="name" placeholder="example.com." />
      <input id="type" placeholder="A" style="max-width:120px" />
      <button onclick="test()">Query</button>
    </div>
    <pre id="out"></pre>
  </div>

  <div class="card">
    <h3>CSV format</h3>
    <pre>name,type,ttl,data,rcode
example.com.,A,300,1.2.3.4,
example.com.,TXT,300,"[\"v=spf1 -all\",\"hello=world\"]",
notfound.example.com.,,,,NXDOMAIN

google.com.,DOH,,https://dns.google/dns-query,ROUTE
openai.com.,UDP,,1.1.1.1,ROUTE</pre>
  </div>

<script>
  async function test(){
    const name=document.getElementById("name").value.trim();
    const type=(document.getElementById("type").value.trim()||"A").toUpperCase();
    const out=document.getElementById("out");
    out.textContent="Loading...";
    try{
      const res=await fetch("/resolve?name="+encodeURIComponent(name)+"&type="+encodeURIComponent(type));
      const data=await res.json();
      out.textContent=JSON.stringify(data,null,2);
    }catch(e){ out.textContent="Error: "+e.message; }
  }
</script>
</body>
</html>`;
}

// 构造一个 SERVFAIL 响应（用于上游失败兜底）
function buildLocalServfail(queryMsg){
  const q = parseDnsQuery(queryMsg);
  const header = new Uint8Array(12);
  writeU16(header, 0, q.id);
  const rd = (q.flags & 0x0100) ? 0x0100 : 0;
  const flags = 0x8000 | 0x0400 | rd | 0x0080 | 2; // SERVFAIL
  writeU16(header, 2, flags);
  writeU16(header, 4, 1);
  writeU16(header, 6, 0);
  writeU16(header, 8, 0);
  writeU16(header, 10, 0);
  const question = concatBytes([
    encodeName(q.qname),
    new Uint8Array([ (q.qtype>>8)&0xff, q.qtype&0xff, (q.qclass>>8)&0xff, q.qclass&0xff ])
  ]);
  return concatBytes([header, question]);
}

export default {
  async fetch(request, env, ctx){
    const url=new URL(request.url);
    const cfg=await loadConfig(env);

    if (request.method==="GET" && url.pathname==="/"){
      if (String(env.ENABLE_WEBUI||"true")==="false") return new Response("Not found",{status:404});
      return new Response(htmlPage(cfg, env), { headers:{ "content-type":"text/html; charset=utf-8" }});
    }

    if (request.method==="GET" && url.pathname==="/resolve"){
      return new Response(JSON.stringify(jsonResolve(cfg,url),null,2), {
        headers:{ "content-type":"application/json; charset=utf-8" }
      });
    }

    if (request.method==="GET" && url.pathname==="/dns-query"){
      const b64=url.searchParams.get("dns");
      if (!b64) return new Response("missing dns param",{status:400});
      const query=b64uToBytes(b64);

      const q = parseDnsQuery(query);
      const rule = findRule(cfg, q.qname);

      if (rule && (rule.records || rule.rcode)) {
        const resp = buildLocalResponse(query, cfg);
        return new Response(resp, { headers:{ "content-type":"application/dns-message" }});
      }

      try {
        if (rule?.route) {
          const upstream = await routeResolve(query, rule.route);
          return new Response(upstream, { headers:{ "content-type":"application/dns-message" }});
        }
        const cf = await resolveViaDoh(query, "https://cloudflare-dns.com/dns-query");
        return new Response(cf, { headers:{ "content-type":"application/dns-message" }});
      } catch (e) {
        const fail = buildLocalServfail(query);
        return new Response(fail, { headers:{ "content-type":"application/dns-message" }});
      }
    }

    if (request.method==="POST" && url.pathname==="/dns-query"){
      const ct=request.headers.get("content-type")||"";
      if (!ct.includes("application/dns-message")) return new Response("unsupported content-type",{status:415});
      const query=new Uint8Array(await request.arrayBuffer());

      const q = parseDnsQuery(query);
      const rule = findRule(cfg, q.qname);

      if (rule && (rule.records || rule.rcode)) {
        const resp = buildLocalResponse(query, cfg);
        return new Response(resp, { headers:{ "content-type":"application/dns-message" }});
      }

      try {
        if (rule?.route) {
          const upstream = await routeResolve(query, rule.route);
          return new Response(upstream, { headers:{ "content-type":"application/dns-message" }});
        }
        const cf = await resolveViaDoh(query, "https://cloudflare-dns.com/dns-query");
        return new Response(cf, { headers:{ "content-type":"application/dns-message" }});
      } catch (e) {
        const fail = buildLocalServfail(query);
        return new Response(fail, { headers:{ "content-type":"application/dns-message" }});
      }
    }

    return new Response("Not found",{status:404});
  }
};
