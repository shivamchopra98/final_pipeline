import React from "react";

export default function OverviewCards({ totalFindings, vrrAvg, uniqueHosts }: any) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
      <div className="bg-slate-800 p-4 rounded shadow">
        <div className="text-sm text-slate-400">Total Findings</div>
        <div className="text-2xl font-bold">{totalFindings}</div>
      </div>

      <div className="bg-slate-800 p-4 rounded shadow">
        <div className="text-sm text-slate-400">Average VRR</div>
        <div className="text-2xl font-bold">{vrrAvg}</div>
      </div>

      <div className="bg-slate-800 p-4 rounded shadow">
        <div className="text-sm text-slate-400">Unique Hosts</div>
        <div className="text-2xl font-bold">{uniqueHosts}</div>
      </div>
    </div>
  );
}
