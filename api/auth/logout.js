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


/* =========================================================
   ALLOWED APPLICATION ORIGINS
   ========================================================= */

const ALLOWED_ORIGINS = new Set([
  "https://neyo.signaturesi.com",
  "https://uasset.signaturesi.com",
  "https://uassets888.vercel.app",
  "https://accounts.signaturesi.com",
  "http://localhost:5173",
  "http://localhost:4173"
]);


/* =========================================================
   CORS
   ========================================================= */

function setCors(req, res) {
  const origin =
    req.headers.origin;

  if (!origin) {
    return true;
  }

  if (
    !ALLOWED_ORIGINS.has(
      origin
    )
  ) {
    res.status(403).json({
      error:
        "Origin not allowed"
    });

    return false;
  }

  res.setHeader(
    "Access-Control-Allow-Origin",
    origin
  );

  res.setHeader(
    "Vary",
    "Origin"
  );

  res.setHeader(
    "Access-Control-Allow-Credentials",
    "true"
  );

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type"
  );

  return true;
}


/* =========================================================
   COOKIE READER
   ========================================================= */

function getCookie(
  req,
  name
) {
  const cookies =
    String(
      req.headers.cookie || ""
    ).split(";");

  for (const cookie of cookies) {
    const [
      key,
      ...valueParts
    ] =
      cookie
        .trim()
        .split("=");

    if (
      key === name
    ) {
      return decodeURIComponent(
        valueParts.join("=")
      );
    }
  }

  return null;
}


/* =========================================================
   TOKEN HASH
   ========================================================= */

function hashToken(
  token
) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}


/* =========================================================
   LOGOUT HANDLER
   ========================================================= */

export default async function handler(
  req,
  res
) {
  res.setHeader(
    "Cache-Control",
    "no-store"
  );


  /* =======================================================
     CORS
     ======================================================= */

  if (
    !setCors(
      req,
      res
    )
  ) {
    return;
  }


  /* =======================================================
     PREFLIGHT
     ======================================================= */

  if (
    req.method ===
    "OPTIONS"
  ) {
    res.setHeader(
      "Access-Control-Allow-Methods",
      "POST, OPTIONS"
    );

    return res
      .status(204)
      .end();
  }


  /* =======================================================
     METHOD CHECK
     ======================================================= */

  if (
    req.method !==
    "POST"
  ) {
    res.setHeader(
      "Allow",
      "POST, OPTIONS"
    );

    return res
      .status(405)
      .json({
        error:
          "Method not allowed"
      });
  }


  /* =======================================================
     COOKIE
     ======================================================= */

  const cookieName =
    process.env.SESSION_COOKIE_NAME ||
    "bean_session";

  const rawToken =
    getCookie(
      req,
      cookieName
    );


  /* =======================================================
     REVOKE SESSION
     ======================================================= */

  try {
    if (rawToken) {
      const tokenHash =
        hashToken(
          rawToken
        );

      const { error } =
        await supabase
          .from(
            "bean_sessions"
          )
          .update({
            revoked_at:
              new Date().toISOString()
          })
          .eq(
            "token_hash",
            tokenHash
          )
          .is(
            "revoked_at",
            null
          );

      if (error) {
        console.error(
          "Logout session revoke failed:",
          error
        );
      }
    }


    /* =====================================================
       CLEAR COOKIE
       ===================================================== */

    res.setHeader(
      "Set-Cookie",
      `${cookieName}=; Path=/; Domain=.signaturesi.com; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
    );


    return res
      .status(200)
      .json({
        success: true
      });

  } catch (error) {
    console.error(
      "Logout exception:",
      error
    );


    /* =====================================================
       ALWAYS CLEAR COOKIE
       ===================================================== */

    res.setHeader(
      "Set-Cookie",
      `${cookieName}=; Path=/; Domain=.signaturesi.com; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
    );


    return res
      .status(200)
      .json({
        success: true
      });
  }
}
