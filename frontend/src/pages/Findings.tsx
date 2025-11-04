import { FindingsFunnel } from "@/components/FindingsFunnel";
import { HostFindingsTable } from "@/components/HostFindingsTable";
import { mockData } from "@/data/mockData";

export default function Findings() {
  return (
    <div className="space-y-8 animate-fade-in">
      <div>
        <h1 className="text-3xl font-bold text-foreground mb-2">Vulnerability Findings</h1>
        <p className="text-muted-foreground">
          Detailed analysis of security vulnerabilities across your infrastructure
        </p>
      </div>

      {/* Severity Funnel */}
      <FindingsFunnel data={mockData.severityDistribution} />

      {/* Detailed Findings Table */}
      <HostFindingsTable data={mockData.findingsTable} />
    </div>
  );
}
