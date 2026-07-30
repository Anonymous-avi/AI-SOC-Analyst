const API_BASE = "https://ai-soc-analyst-aphj.onrender.com";

export async function downloadReport(alertId) {

    const response = await fetch(
        `${API_BASE}/reports/${alertId}`
    );

    if (!response.ok) {
        throw new Error("Failed to download report");
    }

    const blob = await response.blob();

    const url = window.URL.createObjectURL(blob);

    const link = document.createElement("a");

    link.href = url;

    link.download = `Incident_Report_${alertId}.pdf`;

    document.body.appendChild(link);

    link.click();

    link.remove();

    window.URL.revokeObjectURL(url);
}