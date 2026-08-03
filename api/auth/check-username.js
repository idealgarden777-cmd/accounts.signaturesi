import { createClient } from "@supabase/supabase-js";

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

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");

    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  const username = normalizeUsername(req.query.username);

  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({
      error: "Invalid Bean ID"
    });
  }

  try {
    const { data, error } = await supabase
      .from("bean_users")
      .select("id")
      .eq("username", username)
      .maybeSingle();

    if (error) {
      console.error("Bean ID check error:", error);

      return res.status(500).json({
        error: "Unable to check Bean ID"
      });
    }

    return res.status(200).json({
      available: !data
    });
  } catch (error) {
    console.error("Bean ID check exception:", error);

    return res.status(500).json({
      error: "Unable to check Bean ID"
    });
  }
}
