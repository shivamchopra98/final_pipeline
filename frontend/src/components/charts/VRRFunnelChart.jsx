import React from "react";
import Plot from "react-plotly.js";

const VRRFunnelChart = ({ data }) => {
  const counts = { Critical: 10, High: 20, Medium: 15, Low: 8 };

  return (
    <div className="bg-white p-4 rounded-lg shadow-md">
      <h2 className="text-lg font-semibold mb-2">VRR Score Funnel</h2>
      <Plot
        data={[
          {
            type: "funnelarea",
            text: Object.keys(counts),
            values: Object.values(counts),
            marker: { colors: ["#660000", "#cc0000", "#e06666", "#f4cccc"] },
          },
        ]}
        layout={{
          height: 400,
          margin: { t: 30, b: 20, l: 10, r: 10 },
        }}
        config={{ displayModeBar: false }}
      />
    </div>
  );
};

export default VRRFunnelChart;
