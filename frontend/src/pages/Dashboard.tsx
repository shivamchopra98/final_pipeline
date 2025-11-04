import { GaugeChart } from "@/components/GaugeChart";
import { OverviewCards } from "@/components/OverviewCards";
import { FindingsFunnel } from "@/components/FindingsFunnel";
import { mockData } from "@/data/mockData";

export default function Dashboard() {
  return (
    <div className="space-y-8 animate-fade-in">
      <div>
        <h1 className="text-3xl font-bold text-foreground mb-2">Risk Score Dashboard</h1>
        <p className="text-muted-foreground">
          Monitor your organization's security posture in real-time
        </p>
      </div>

      {/* Risk Score Gauges */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <GaugeChart value={mockData.riskScore.overall} title="Overall RS³ Score" />
        <GaugeChart value={mockData.riskScore.weaponized} title="Weaponized Findings" />
        <GaugeChart value={mockData.riskScore.application} title="Application Risk Score" />
      </div>

      {/* Findings Overview */}
      <div>
        <h2 className="text-2xl font-bold text-foreground mb-4">Findings Overview</h2>
        <OverviewCards data={mockData.findingsSummary} />
      </div>

      {/* Open Findings by Severity */}
      <FindingsFunnel data={mockData.severityDistribution} />
    </div>
  );
}
