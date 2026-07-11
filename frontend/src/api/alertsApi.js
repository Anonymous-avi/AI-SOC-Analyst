const API_BASE_URL = "http://127.0.0.1:8000";


export async function fetchAlerts() {

  const response = await fetch(
    `${API_BASE_URL}/alerts/`
  );

  if (!response.ok) {
    throw new Error("Failed to fetch alerts");
  }

  return response.json();
}


export async function fetchAlertById(alertId) {

  const response = await fetch(
    `${API_BASE_URL}/alerts/${encodeURIComponent(alertId)}`
  );

  if (!response.ok) {

    if (response.status === 404) {
      throw new Error("Alert not found");
    }

    throw new Error("Failed to fetch alert");
  }

  return response.json();
}