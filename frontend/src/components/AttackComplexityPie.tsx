import React, { useMemo } from "react";
import Plot from "react-plotly.js";

/**
 * Attack Complexity distribution:
 * We try to extract attack complexity from enriched fields (if present),
 * otherwise fallback to categorize by severity text.
 */
export default function AttackComplexityPie({ data }: any) {
  const counts = useMemo(() => {
    const low: number[] = [];
    let simple = 0, complex = 0, unknown = 0;
    (data || []).forEach((r: any) => {
      // first try to inspect nested enriched metrics if present
      const enriched = r["metrics"] || r["IBM"] || r["packet"] || r["Intruder"] || {};
      const ac = (enriched && (enriched["ibm_attack_complexity"] || enriched["attack_complexity"] || enriched["attack_complexity_enriched"])) || null;
      if (ac) {
        const s = String(ac).toLowerCase();
        if (s.includes("low") || s.includes("simple") || s.includes("easy")) simple++;
        else if (s.includes("high") || s.includes("complex") || s.includes("hard")) complex++;
        else unknown++;
      } else {
        const sev = String(r["Scanner Reported Severity"] || "").toLowerCase();
        if (sev.includes("critical") || sev.includes("high")) complex++;
        else if (sev.includes("medium") || sev.includes("low")) simple++;
        else unknown++;
      }
    });
    return { simple, complex, unknown };
  }, [data]);

  const labels = ["Simple", "Complex", "Unknown"];
  const values = [counts.simple, counts.complex, counts.unknown];

  return (
    <Plot
      data={[
        {
          type: "pie",
          labels,
          values,
          marker: { colors: ["#84cc16", "#ef4444", "#94a3b8"] },
          textinfo: "label+percent",
        },
      ]}
      layout={{
        margin: { t: 0, b: 0, l: 0, r: 0 },
        showlegend: false,
        font: { color: "#e6eef8" },
        paper_bgcolor: "rgba(0,0,0,0)",
      }}
      style={{ width: "100%", height: "280px" }}
      config={{ displayModeBar: false }}
    />
  );
}
