interface SeverityData {
  severity: string;
  percent: number;
  openFindings: number;
  assets: number;
  color: string;
}

interface FindingsFunnelProps {
  data: SeverityData[];
}

export function FindingsFunnel({ data }: FindingsFunnelProps) {
  return (
    <div className="bg-card rounded-lg border border-border p-8">
      <h2 className="text-2xl font-bold text-card-foreground mb-8">
        Open Findings by Severity
      </h2>
      <div className="flex flex-col items-center space-y-4 max-w-3xl mx-auto">
        {data.map((item, index) => {
          const width = 100 - index * 20; // Decreasing width for funnel effect
          return (
            <div
              key={item.severity}
              className="relative transition-all duration-300 hover:scale-105 cursor-pointer"
              style={{ width: `${width}%` }}
            >
              <div
                className="rounded-lg p-6 flex items-center justify-between shadow-md"
                style={{ backgroundColor: item.color }}
              >
                <div className="flex flex-col text-white">
                  <span className="text-xl font-bold">{item.severity}</span>
                  <span className="text-sm opacity-90">{item.percent}% of findings</span>
                </div>
                <div className="flex flex-col items-end text-white">
                  <span className="text-2xl font-bold">
                    {item.openFindings.toLocaleString()}
                  </span>
                  <span className="text-sm opacity-90">
                    {item.assets.toLocaleString()} assets
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
