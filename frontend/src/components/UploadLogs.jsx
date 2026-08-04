import { useRef, useState } from "react";
import { FileUp, Upload, ShieldAlert } from "lucide-react";

import { uploadLog } from "../api/alertsApi";

function UploadLogs({ onUploadSuccess }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState("");
  const [isDragging, setIsDragging] = useState(false);
  const inputRef = useRef(null);

  function setFile(file) {
    if (!file) {
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
    setMessage("");
  }

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

  function handleDrop(event) {
    event.preventDefault();
    setIsDragging(false);

    const file = event.dataTransfer.files?.[0];
    setFile(file);
  }

  return (
    <div className="upload-card card-surface">
      <div className="chart-card-header">
        <div className="flex items-center gap-3">
          <span className="soc-logo">
            <ShieldAlert size={18} />
          </span>

          <div>
            <h2 className="section-title">Upload Security Logs</h2>
            <p className="section-subtitle">
              Drag and drop one or more raw logs to start normalization and threat detection.
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={() => inputRef.current?.click()}
          className="secondary-button"
        >
          <FileUp size={16} />
          Choose File
        </button>
      </div>

      <div
        className={`dropzone ${isDragging ? "active" : ""}`}
        onDragOver={(event) => {
          event.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        role="button"
        tabIndex={0}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".txt,.log"
          onChange={(e) => setFile(e.target.files?.[0])}
          className="hidden"
        />

        <div className="flex items-start gap-4">
          <div className="metric-icon">
            <Upload size={20} />
          </div>

          <div>
            <p className="section-title">Drop log files here</p>
            <p className="section-subtitle">
              Supports text-based logs used by the parser and normalization services.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-sm text-[var(--text-muted)]">
          <span className="chip">TXT</span>
          <span className="chip">LOG</span>
          <span className="chip">Multi-file ready</span>
        </div>

        {selectedFile ? (
          <div className="rounded-2xl border border-[var(--border)] bg-white/5 px-4 py-3 text-sm text-[var(--text-soft)]">
            Selected file: <span className="font-semibold text-[var(--text)]">{selectedFile.name}</span>
          </div>
        ) : null}
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button
          onClick={handleUpload}
          disabled={uploading}
          className="primary-button"
        >
          {uploading ? "Uploading..." : "Upload and Analyze"}
        </button>

        <span className="subtle-text text-sm">
          Files are validated before the backend analyzer runs.
        </span>
      </div>

      {message && (
        <p className="mt-4 text-sm text-[var(--text-soft)]">
          {message}
        </p>
      )}
    </div>
  );
}

export default UploadLogs;