import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { uploadFile } from "@/lib/api";
import { useData } from "@/hooks/DataContext";

export default function UploadPage() {
  const { setData, setCsv, setScanner } = useData();
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const onFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setError(null);
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      setProgress(1);
      const json = await uploadFile(file, (p) => setProgress(p));
      if (json.error) {
        setError(json.error);
        setProgress(null);
        return;
      }
      setData(json.data || []);
      setCsv(json.csv || null);
      setScanner(json.scanner || null);
      setProgress(null);
      // navigate to dashboard
      navigate("/dashboard");
    } catch (err: any) {
      console.error(err);
      setError(err?.response?.data?.error || err.message || "Upload failed");
      setProgress(null);
    }
  };

  return (
    <div className="max-w-3xl mx-auto bg-slate-800 p-6 rounded-lg shadow">
      <h2 className="text-2xl font-semibold mb-4">Upload Input File</h2>

      <p className="mb-4 text-slate-300">Supported: .csv, .xlsx, .json, .xml</p>

      <input
        type="file"
        onChange={onFile}
        accept=".csv,.xlsx,.json,.xml"
        className="mb-4"
      />

      {progress !== null && (
        <div className="mb-3">
          <div className="w-full bg-slate-700 h-3 rounded overflow-hidden">
            <div style={{ width: `${progress}%` }} className="bg-emerald-400 h-3" />
          </div>
          <div className="text-sm mt-1">Uploading & processing: {progress}%</div>
        </div>
      )}

      {error && <div className="text-red-400 mt-3">Error: {error}</div>}
    </div>
  );
}
