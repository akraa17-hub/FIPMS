// ============================================================
// FIPMS — دالة إدارة المستخدمين (Supabase Edge Function)
// الاسم عند النشر: manage-users
// ============================================================
// تنفيذ: supabase functions deploy manage-users
// سر الخدمة (SERVICE_ROLE) يُحقن تلقائياً من بيئة المشروع — لا يوضع في المتصفح أبداً

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const ALLOWED_ROLES = ["مالك", "مشرف", "محرر", "مطالع"];

Deno.serve(async (req) => {
  const headers = { "Content-Type": "application/json" };
  const authHeader = req.headers.get("Authorization") || "";
  const token = authHeader.replace("Bearer ", "");

  const serviceClient = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { autoRefreshToken: false, persistSession: false } }
  );

  let caller;
  try {
    const { data: { user } } = await serviceClient.auth.getUser(token);
    caller = user;
  } catch {
    return new Response(JSON.stringify({ ok: false, error: "unauthorized" }), { status: 401, headers });
  }
  if (!caller) return new Response(JSON.stringify({ ok: false, error: "unauthorized" }), { status: 401, headers });

  // التحقق من صلاحية المستدعي
  const { data: roleRow } = await serviceClient
    .from("user_roles").select("role").eq("email", caller.email).maybeSingle();
  const role = roleRow?.role || "مطالع";
  const { data: roleDef } = await serviceClient
    .from("roles").select("permissions").eq("name", role).maybeSingle();
  const perms = roleDef?.permissions || [];
  if (!perms.includes("manage_users")) {
    return new Response(JSON.stringify({ ok: false, error: "forbidden" }), { status: 403, headers });
  }
  const isOwner = perms.includes("manage_connection");

  let body;
  try { body = await req.json(); } catch { body = {}; }
  const action = body.action || "";

  try {
    if (action === "listUsers") {
      const { data } = await serviceClient.auth.admin.listUsers({ perPage: 1000 });
      const { data: roles } = await serviceClient.from("user_roles").select("email, role");
      const roleMap = Object.fromEntries((roles || []).map(r => [r.email, r.role]));
      const users = (data?.users || []).map(u => ({
        id: u.id,
        email: u.email,
        role: roleMap[u.email] || "بدون دور",
        banned: !!u.banned_until,
        created_at: u.created_at,
      }));
      return new Response(JSON.stringify({ ok: true, users }), { headers });
    }

    if (action === "createUser") {
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      const newRole = ALLOWED_ROLES.includes(body.role) ? body.role : "مطالع";
      if (!email || password.length < 6) {
        return new Response(JSON.stringify({ ok: false, error: "invalid_input", message: "بريد غير صالح أو كلمة مرور أقل من 6 أحرف" }), { headers });
      }
      if (newRole === "مالك" && !isOwner) {
        return new Response(JSON.stringify({ ok: false, error: "forbidden", message: "منح دور المالك حصري للمالك الحالي" }), { status: 403, headers });
      }
      const { data, error } = await serviceClient.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
      });
      if (error) {
        return new Response(JSON.stringify({ ok: false, error: error.name || "create_failed", code: error.status, message: error.message }), { headers });
      }
      const { error: rErr } = await serviceClient.from("user_roles").upsert({ email, role: newRole });
      if (rErr) {
        return new Response(JSON.stringify({ ok: false, error: "role_failed", message: "أُنشئ الحساب لكن تعذر ربط الدور: " + rErr.message }), { headers });
      }
      return new Response(JSON.stringify({ ok: true, id: data.user.id }), { headers });
    }

    if (action === "resetPassword") {
      const id = String(body.id || "");
      const password = String(body.password || "");
      if (!id || password.length < 6) {
        return new Response(JSON.stringify({ ok: false, error: "invalid" }), { headers });
      }
      const { error } = await serviceClient.auth.admin.updateUserById(id, { password });
      if (error) return new Response(JSON.stringify({ ok: false, error: error.message }), { headers });
      return new Response(JSON.stringify({ ok: true }), { headers });
    }

    if (action === "disableUser") {
      const id = String(body.id || "");
      const { error } = await serviceClient.auth.admin.updateUserById(id, { ban_duration: "876000h" });
      if (error) return new Response(JSON.stringify({ ok: false, error: error.message }), { headers });
      return new Response(JSON.stringify({ ok: true }), { headers });
    }

    if (action === "enableUser") {
      const id = String(body.id || "");
      const { error } = await serviceClient.auth.admin.updateUserById(id, { ban_duration: "none" });
      if (error) return new Response(JSON.stringify({ ok: false, error: error.message }), { headers });
      return new Response(JSON.stringify({ ok: true }), { headers });
    }

    return new Response(JSON.stringify({ ok: false, error: "unknown_action" }), { headers });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: String(err?.message || err) }), { headers });
  }
});
