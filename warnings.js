// Browser-side warning adapter.
//
// app.js calls buildWarning(scenario, result) and renders the returned string directly.
// The server builds it from the rewriter's Romanian templates, with the official-contact
// guard applied, together with the detector result — so this costs no extra request.

export async function buildWarning(scenario, result) {
  const text = result?.warning_text;
  return typeof text === "string" && text.trim() ? text : null;
}
