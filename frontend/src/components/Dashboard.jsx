import React from "react";
import Metrics from "./Metrics";
import VulnerabilitiesTable from "./VulnerabilitiesTable";
import VRRFunnelChart from "./Charts/VRRFunnelChart";

const Dashboard = ({ data }) => {
  if (!data) {
    return <div className="text-gray-500">👉 Upload a CSV file to view data</div>;
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">🛡️ Cyber Threat Intelligence Dashboard</h1>
      <Metrics data={data} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <VRRFunnelChart data={data} />
        <VulnerabilitiesTable data={data} />
      </div>
    </div>
  );
};

export default Dashboard;
