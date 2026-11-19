// Browser-side detector adapter.
//
// app.js imports this module and calls analyzeScenario(scenario). The real detection
// runs in Python (scam_detector, offline MiniLM + rules) behind POST /api/analyze, so
// the page and the CLI always agree on the answer.

const ENDPOINT = "./api/analyze";

export async function analyzeScenario(scenario) {
  let response;
  try {
    response = await fetch(ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(scenario),
    });
  } catch {
    throw new Error("Serverul local nu răspunde. Porniți aplicația cu python3 server.py.");
  }

  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(detail.error || `Detectorul a răspuns cu eroarea ${response.status}.`);
  }

  const result = await response.json();
  // app.js validates verdict / risk_score / scam_type / first_alert / red_flags and
  // expects red_flags as [{ code, message_number }]; the server already sends that shape.
  return result;
}
