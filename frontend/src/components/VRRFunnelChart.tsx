import React from "react";
import Plot from "react-plotly.js";

export default function VRRFunnelChart({ counts }: any) {
  const labels = ["Critical", "High", "Medium", "Low", "Info"];
  const values = [
    counts.critical || 0,
    counts.high || 0,
    counts.medium || 0,
    counts.low || 0,
    counts.info || 0,
  ];

  const total = values.reduce((a, b) => a + b, 0);
  const percentages = values.map((v) => (total ? ((v / total) * 100).toFixed(1) : "0"));
  const textLabels = labels.map(
    (label, i) => `${label}: ${values[i].toLocaleString()} (${percentages[i]}%)`
  );

  return (
    <Plot
      data={[
        {
          type: "funnelarea",
          values,
          labels,
          text: textLabels,
          textposition: "inside",
          textinfo: "text",
          textfont: {
            color: "#fff",
            size: 16,
          },
          marker: {
            colors: ["#991b1b", "#dc2626", "#f97316", "#84cc16", "#3b82f6"],
            line: { color: "#0f172a", width: 2 },
          },
          opacity: 0.95,
        },
      ]}
      layout={{
        title: {
          text: "Findings Prioritization Funnel",
          font: { size: 22, color: "#f8fafc", family: "Inter, sans-serif" },
          x: 0.02,
          xanchor: "left",
        },
        showlegend: true,
        legend: {
          x: 1.05,
          y: 1,
          font: { color: "#e2e8f0" },
          bgcolor: "rgba(0,0,0,0)",
        },
        margin: { t: 60, l: 40, r: 200, b: 60 },
        paper_bgcolor: "rgba(0,0,0,0)",
        plot_bgcolor: "rgba(0,0,0,0)",
        autosize: true,
        height: 500,
      }}
      config={{
        displayModeBar: false,
        responsive: true,
      }}
      style={{ width: "100%", height: "500px" }}
    />
  );
}
