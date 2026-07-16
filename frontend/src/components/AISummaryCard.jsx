import { useEffect, useState } from "react";
import { fetchAISummary } from "../api/aiApi";

function AISummaryCard({ alertId }) {
  const [summary, setSummary] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadSummary() {
      try {
        setLoading(true);

        const data = await fetchAISummary(alertId);

        setSummary(data.summary);
      } catch (err) {
        console.error(err);
        setSummary("Failed to generate AI summary.");
      } finally {
        setLoading(false);
      }
    }

    if (alertId) {
      loadSummary();
    }
  }, [alertId]);

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
      <h2 className="mb-4 text-xl font-bold text-white">
        AI Security Summary
      </h2>

      {loading ? (
        <p className="text-slate-400">
          Generating AI analysis...
        </p>
      ) : (
        <pre className="whitespace-pre-wrap text-slate-300">
          {summary}
        </pre>
      )}
    </div>
  );
}

export default AISummaryCard;