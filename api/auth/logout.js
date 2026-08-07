import { createClient } from "@supabase/supabase-js";
import crypto from "node:crypto";

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

function getCookie(req, name) {
  const cookies = String(req.headers.cookie || "").split(";");

  for (const cookie of cookies) {
    const [key, ...valueParts] = cookie.trim().split("=");

    if (key === name) {
      return decodeURIComponent(valueParts.join("="));
    }
  }

  return null;
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

export default async function handler(req, res) {
  // ✅ CORS headers
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Access-Control-Allow-Origin", "https://neyo.signaturesi.com");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  // ✅ Handle preflight OPTIONS
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    return res.status(204).end();
  }

  // ✅ Only POST allowed
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  const cookieName = process.env.SESSION_COOKIE_NAME || "bean_session";
  const rawToken = getCookie(req, cookieName);

  try {
    if (rawToken) {
      const tokenHash = hashToken(rawToken);

      const { error } = await supabase
        .from("bean_sessions")
        .update({
          revoked_at: new Date().toISOString()
        })
        .eq("token_hash", tokenHash)
        .is("revoked_at", null);

      if (error) {
        console.error("Logout session revoke failed:", error);
      }
    }

    // ✅ Clear cookie with domain
    res.setHeader(
      "Set-Cookie",
      `${cookieName}=; Path=/; Domain=.signaturesi.com; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
    );

    return res.status(200).json({
      success: true
    });
  } catch (error) {
    console.error("Logout exception:", error);

    // ✅ Even on error, clear cookie with domain
    res.setHeader(
      "Set-Cookie",
      `${cookieName}=; Path=/; Domain=.signaturesi.com; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
    );

    return res.status(200).json({
      success: true
    });
  }
}
