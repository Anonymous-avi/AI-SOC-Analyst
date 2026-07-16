import { useState } from "react";
import { Upload } from "lucide-react";

import { uploadLog } from "../api/alertsApi";

function UploadLogs({ onUploadSuccess }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState("");

  async function handleUpload() {
    if (!selectedFile) {
      setMessage("Please select a log file.");
      return;
    }

    try {
      setUploading(true);
      setMessage("");

      await uploadLog(selectedFile);

      setMessage("✅ Log uploaded successfully.");

      setSelectedFile(null);

      if (onUploadSuccess) {
        onUploadSuccess();
      }
    } catch (error) {
      console.error(error);
      setMessage("❌ Upload failed.");
    } finally {
      setUploading(false);
    }
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
      <div className="mb-5 flex items-center gap-3">
        <Upload className="h-6 w-6 text-cyan-400" />

        <h2 className="text-lg font-semibold text-white">
          Upload Security Logs
        </h2>
      </div>

      <input
        type="file"
        accept=".txt,.log"
        onChange={(e) =>
          setSelectedFile(e.target.files[0])
        }
        className="mb-4 block w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-slate-300"
      />

      <button
        onClick={handleUpload}
        disabled={uploading}
        className="rounded-lg bg-cyan-600 px-5 py-2 font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
      >
        {uploading ? "Uploading..." : "Upload Logs"}
      </button>

      {message && (
        <p className="mt-4 text-sm text-slate-300">
          {message}
        </p>
      )}
    </div>
  );
}

export default UploadLogs;