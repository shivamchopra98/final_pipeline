import React from "react";
import Plot from "react-plotly.js";

export default function SeverityBreakdownBar({ counts }: any) {
  const labels = ["Critical", "High", "Medium", "Low", "Info"];
  const values = [
    counts.critical || 0,
    counts.high || 0,
    counts.medium || 0,
    counts.low || 0,
    counts.info || 0,
  ];

  const total = values.reduce((a, b) => a + b, 0);
  const percentages = values.map((v) =>
    total ? ((v / total) * 100).toFixed(1) : "0"
  );

  return (
    <Plot
      data={[
        {
          type: "bar",
          x: values,
          y: labels,
          orientation: "h",
          text: percentages.map((p, i) => `${values[i]} (${p}%)`),
          textposition: "auto",
          textfont: { color: "#f8fafc", size: 14 },
          marker: {
            color: ["#991b1b", "#dc2626", "#f97316", "#84cc16", "#3b82f6"],
          },
          hoverinfo: "text",
        },
      ]}
      layout={{
        title: {
          text: "Severity Breakdown (Counts & %)",
          font: { size: 20, color: "#f8fafc" },
          x: 0.02,
        },
        xaxis: {
          title: "Number of Findings",
          color: "#94a3b8",
          gridcolor: "#334155",
        },
        yaxis: {
          color: "#94a3b8",
        },
        margin: { t: 50, l: 100, r: 40, b: 50 },
        height: 400,
        paper_bgcolor: "rgba(0,0,0,0)",
        plot_bgcolor: "rgba(0,0,0,0)",
        autosize: true,
      }}
      config={{
        displayModeBar: false,
        responsive: true,
      }}
      style={{ width: "100%", height: "400px" }}
    />
  );
}
