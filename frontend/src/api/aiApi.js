const API_BASE = "http://127.0.0.1:8000";

export async function fetchAISummary(alertId) {
  const response = await fetch(`${API_BASE}/ai/summary`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      alert_id: alertId,
    }),
  });

  if (!response.ok) {
    throw new Error("Failed to generate AI summary");
  }

  return response.json();
}