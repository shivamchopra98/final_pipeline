import axios from "axios";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

export async function uploadFile(file: File, onUploadProgress?: (p: number) => void) {
  const form = new FormData();
  form.append("input_file", file); // backend expects field name input_file
  const resp = await axios.post(`${API_BASE}/generate-unified-output/`, form, {
    headers: { "Content-Type": "multipart/form-data" },
    onUploadProgress: (ev) => {
      if (onUploadProgress && ev.total) onUploadProgress(Math.round((ev.loaded / ev.total) * 100));
    },
    timeout: 15 * 60 * 1000, // long timeout for big files
  });
  return resp.data;
}
