import React from "react";
import { useData } from "@/hooks/DataContext";
import FindingsTable from "../components/FindingsTable";

export default function FindingsPage() {
  const { data } = useData();

  if (!data || data.length === 0)
    return (
      <div className="text-slate-300">
        No findings yet — upload a file first.
      </div>
    );

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-4">All Vulnerability Findings</h2>
      <div className="bg-slate-800 p-4 rounded shadow">
        <FindingsTable rows={data} />
      </div>
    </div>
  );
}
