const API_BASE_URL = "https://ai-soc-analyst-aphj.onrender.com";


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
export async function uploadLog(file) {
  const formData = new FormData();

  formData.append("file", file);

  const response = await fetch(
    `${API_BASE_URL}/upload/`,
    {
      method: "POST",
      body: formData,
    }
  );

  if (!response.ok) {
    throw new Error("Failed to upload log");
  }

  return response.json();
}