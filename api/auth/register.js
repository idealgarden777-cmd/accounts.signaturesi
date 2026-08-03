import { createClient } from "@supabase/supabase-js";
import argon2 from "argon2";
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

function normalizeUsername(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^@/, "")
    .replace(/@bean$/i, "");
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");

    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  const username = normalizeUsername(req.body?.username);
  const password = String(req.body?.password || "");

  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({
      error: "Invalid Bean ID"
    });
  }

  if (password.length < 10) {
    return res.status(400).json({
      error: "Password must contain at least 10 characters"
    });
  }

  try {
    const { data: existingUser, error: existingError } = await supabase
      .from("bean_users")
      .select("id")
      .eq("username", username)
      .maybeSingle();

    if (existingError) {
      console.error("Existing user check failed:", existingError);

      return res.status(500).json({
        error: "Unable to create Bean ID"
      });
    }

    if (existingUser) {
      return res.status(409).json({
        error: "This Bean ID is already taken"
      });
    }

    const userId = crypto.randomUUID();

    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id
    });

    const { error: userError } = await supabase
      .from("bean_users")
      .insert({
        id: userId,
        username,
        display_name: username,
        email: null,
        status: "active"
      });

    if (userError) {
      console.error("Bean user insert failed:", userError);

      return res.status(500).json({
        error: "Unable to create Bean ID"
      });
    }

    const { error: credentialError } = await supabase
      .from("bean_credentials")
      .insert({
        user_id: userId,
        password_hash: passwordHash
      });

    if (credentialError) {
      console.error("Credential insert failed:", credentialError);

      await supabase
        .from("bean_users")
        .delete()
        .eq("id", userId);

      return res.status(500).json({
        error: "Unable to create Bean ID"
      });
    }

    const rawToken = crypto.randomBytes(32).toString("base64url");
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(
      Date.now() + 7 * 24 * 60 * 60 * 1000
    ).toISOString();

    const { error: sessionError } = await supabase
      .from("bean_sessions")
      .insert({
        user_id: userId,
        token_hash: tokenHash,
        expires_at: expiresAt,
        user_agent: String(req.headers["user-agent"] || "").slice(0, 500)
      });

    if (sessionError) {
      console.error("Signup session insert failed:", sessionError);

      return res.status(500).json({
        error: "Account created, but automatic login failed"
      });
    }

    const cookieName =
      process.env.SESSION_COOKIE_NAME || "bean_session";

    res.setHeader(
      "Set-Cookie",
      `${cookieName}=${rawToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
    );

    return res.status(201).json({
      success: true,
      user: {
        id: userId,
        username,
        displayName: username,
        beanId: `${username}@bean`
      }
    });
  } catch (error) {
    console.error("Registration exception:", error);

    return res.status(500).json({
      error: "Unable to create Bean ID"
    });
  }
}
