import React, { useMemo } from "react";
import { useData } from "@/hooks/DataContext";
import OverviewCards from "../components/OverviewCards";
import VRRFunnelChart from "../components/VRRFunnelChart";
import AttackComplexityPie from "../components/AttackComplexityPie";
import { saveAs } from "file-saver";

export default function DashboardPage() {
  const { data, csv, scanner } = useData();

  // --- Dynamic average VRR ---
  const vrrAvg = useMemo(() => {
    if (!data?.length) return 0;
    const numericScores = data
      .map((r) => parseFloat(r["VRR Score"]))
      .filter((n) => !isNaN(n));
    if (!numericScores.length) return 0;
    return Number(
      (numericScores.reduce((a, b) => a + b, 0) / numericScores.length).toFixed(2)
    );
  }, [data]);

  // --- Count by severity levels ---
  const severityCounts = useMemo(() => {
    const map: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    (data || []).forEach((r) => {
      const sev = String(
        r["Scanner Reported Severity"] || r["Scanner Severity"] || ""
      ).toLowerCase();
      if (sev.includes("critical")) map.critical++;
      else if (sev.includes("high")) map.high++;
      else if (sev.includes("medium")) map.medium++;
      else if (sev.includes("low")) map.low++;
      else map.info++;
    });
    return map;
  }, [data]);

  const uniqueHosts = useMemo(
    () => new Set((data || []).map((r) => r["IPAddress"] || r["Host"])).size,
    [data]
  );

  if (!data || data.length === 0) {
    return (
      <div className="text-slate-300">
        No data yet. Please upload a file on the Upload page.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-semibold">
          🛡️ Cyber Threat Intelligence Dashboard
        </h2>
        <div className="flex items-center gap-3">
          <div className="text-slate-300">
            Scanner:
            <strong className="text-white ml-2">{scanner || "Unknown"}</strong>
          </div>
          {csv && (
            <button
              className="px-3 py-1 bg-emerald-500 rounded text-slate-900 font-medium"
              onClick={() =>
                saveAs(
                  new Blob([csv], { type: "text/csv;charset=utf-8" }),
                  "unified_output.csv"
                )
              }
            >
              Download CSV
            </button>
          )}
        </div>
      </div>

      <OverviewCards
        totalFindings={data.length}
        vrrAvg={vrrAvg}
        uniqueHosts={uniqueHosts}
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-800 p-4 rounded shadow">
          <h3 className="font-semibold mb-3">Findings Prioritization Funnel</h3>
          <VRRFunnelChart counts={severityCounts} />
        </div>

        <div className="bg-slate-800 p-4 rounded shadow">
          <h3 className="font-semibold mb-3">Attack Complexity Distribution</h3>
          <AttackComplexityPie data={data} />
        </div>
      </div>
    </div>
  );
}
