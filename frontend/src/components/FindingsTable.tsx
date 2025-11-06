import React, { useState, useMemo } from "react";

export default function FindingsTable({ rows }: any) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<any | null>(null);

  const filtered = useMemo(() => {
    if (!query) return rows;
    const q = query.toLowerCase();
    return rows.filter((r: any) =>
      Object.values(r).some((v) => String(v || "").toLowerCase().includes(q))
    );
  }, [rows, query]);

  const headers = Object.keys(rows[0] || {});

  const getSeverityClass = (severity: string) => {
    const s = severity.toLowerCase();
    if (s.includes("critical") || s.includes("high"))
      return "text-red-500 font-bold";
    if (s.includes("medium")) return "text-orange-400 font-bold";
    if (s.includes("low")) return "text-green-400 font-bold";
    return "text-slate-300";
  };

  return (
    <>
      {/* Search bar */}
      <div className="flex items-center gap-3 mb-3">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search..."
          className="bg-slate-700 p-2 rounded w-full"
        />
        <div className="text-slate-400 text-sm">
          Showing {filtered.length} / {rows.length}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto max-h-[70vh] overflow-y-auto">
        <table className="min-w-full text-sm">
          <thead className="sticky top-0 bg-slate-700">
            <tr>
              {["Vulnerability name", "Scanner Reported Severity", "VRR Score", "Host", "Port", "Protocol", "Status"].map((h) => (
                <th key={h} className="px-3 py-2 text-left whitespace-nowrap">
                  {h}
                </th>
              ))}
              <th className="px-3 py-2 text-left">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r: any, i: number) => (
              <tr
                key={i}
                className="border-t border-slate-700 hover:bg-slate-800 cursor-pointer"
              >
                <td className="px-3 py-2">{r["Vulnerability name"]}</td>
                <td className={`px-3 py-2 ${getSeverityClass(r["Scanner Reported Severity"] || "")}`}>
                  {r["Scanner Reported Severity"] || "N/A"}
                </td>
                <td className="px-3 py-2">{r["VRR Score"]}</td>
                <td className="px-3 py-2">{r["IPAddress"]}</td>
                <td className="px-3 py-2">{r["Port"]}</td>
                <td className="px-3 py-2">{r["Protocol"]}</td>
                <td className="px-3 py-2">{r["Status"]}</td>
                <td className="px-3 py-2">
                  <button
                    onClick={() => setSelected(r)}
                    className="px-2 py-1 bg-emerald-500 text-slate-900 rounded hover:bg-emerald-400"
                  >
                    View
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Modal */}
      {selected && (
        <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-70 z-50">
          <div className="bg-slate-800 p-6 rounded-lg max-w-3xl w-full max-h-[90vh] overflow-y-auto shadow-lg">
            <div className="flex justify-between items-center mb-3">
              <h3 className="text-xl font-semibold">Finding Details</h3>
              <button
                onClick={() => setSelected(null)}
                className="text-slate-400 hover:text-white text-xl"
              >
                ✕
              </button>
            </div>
            <div className="text-sm whitespace-pre-wrap">
              {Object.entries(selected).map(([key, value]) => (
                <div key={key} className="mb-2">
                  <span className="text-emerald-400 font-semibold">{key}:</span>{" "}
                  <span className="text-slate-200">
                    {typeof value === "object"
                      ? JSON.stringify(value, null, 2)
                      : String(value || "")}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
