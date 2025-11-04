import React from "react";

const Metrics = ({ data }) => {
  const totalAssets = new Set(data.map(d => d.Host)).size || data.length;
  const totalFindings = data.length;

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
      <MetricCard label="💻 Total Assets" value={totalAssets} />
      <MetricCard label="🚨 Open Findings" value={totalFindings} />
      <MetricCard label="🎯 Weaponized Assets" value="TBD" />
      <MetricCard label="⏱️ Mean Remediation Time" value="225 Days" />
      <MetricCard label="🏷️ Total Tags" value="TBD" />
    </div>
  );
};

const MetricCard = ({ label, value }) => (
  <div className="bg-white shadow-md rounded-lg p-4 text-center">
    <div className="text-xl font-bold">{value}</div>
    <div className="text-sm text-gray-600">{label}</div>
  </div>
);

export default Metrics;
