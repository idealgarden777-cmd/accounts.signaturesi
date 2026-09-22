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
  "https://uasset.signaturesi.com",
  "https://uassets888.vercel.app",
  "https://neyo.signaturesi.com",
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
   SESSION HANDLER
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
      "GET, OPTIONS"
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
    "GET"
  ) {

    res.setHeader(
      "Allow",
      "GET, OPTIONS"
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
     NO SESSION
     ======================================================= */

  if (!rawToken) {
    return res
      .status(200)
      .json({
        authenticated:
          false
      });
  }


  /* =======================================================
     VERIFY SESSION
     ======================================================= */

  try {

    const tokenHash =
      hashToken(
        rawToken
      );


    const {
      data: session,
      error: sessionError
    } =
      await supabase
        .from(
          "bean_sessions"
        )
        .select(
          "user_id, expires_at, revoked_at"
        )
        .eq(
          "token_hash",
          tokenHash
        )
        .maybeSingle();


    if (
      sessionError
    ) {

      console.error(
        "Session lookup failed:",
        sessionError
      );

      return res
        .status(500)
        .json({
          error:
            "Unable to verify session"
        });
    }


    /* =====================================================
       INVALID / EXPIRED / REVOKED
       ===================================================== */

    if (
      !session ||
      session.revoked_at ||
      new Date(
        session.expires_at
      ).getTime() <=
        Date.now()
    ) {

      return res
        .status(200)
        .json({
          authenticated:
            false
        });
    }


    /* =====================================================
       USER
       ===================================================== */

    const {
      data: user,
      error: userError
    } =
      await supabase
        .from(
          "bean_users"
        )
        .select(
          "id, username, display_name, status"
        )
        .eq(
          "id",
          session.user_id
        )
        .maybeSingle();


    if (
      userError
    ) {

      console.error(
        "Session user lookup failed:",
        userError
      );

      return res
        .status(500)
        .json({
          error:
            "Unable to verify session"
        });
    }


    /* =====================================================
       USER NOT ACTIVE
       ===================================================== */

    if (
      !user ||
      user.status !==
        "active"
    ) {

      return res
        .status(200)
        .json({
          authenticated:
            false
        });
    }


    /* =====================================================
       AUTHENTICATED RESPONSE
       ===================================================== */

    return res
      .status(200)
      .json({

        authenticated:
          true,

        user: {

          id:
            user.id,

          username:
            user.username,

          displayName:
            user.display_name,

          beanId:
            `${user.username}@bean`
        }

      });

  } catch (error) {

    console.error(
      "Session verification exception:",
      error
    );

    return res
      .status(500)
      .json({
        error:
          "Unable to verify session"
      });
  }
}
