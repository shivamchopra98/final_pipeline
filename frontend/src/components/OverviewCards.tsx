import { BarChart, Bar, ResponsiveContainer, Cell } from "recharts";

interface OverviewCardProps {
  title: string;
  openFindings: number;
  affectedAssets: number;
  chartData: Array<{ value: number }>;
}

export function OverviewCard({
  title,
  openFindings,
  affectedAssets,
  chartData,
}: OverviewCardProps) {
  return (
    <div className="bg-card rounded-lg border border-border p-6 hover:shadow-lg transition-shadow">
      <h3 className="text-lg font-semibold text-card-foreground mb-4">{title}</h3>
      <div className="space-y-2 mb-4">
        <div className="flex justify-between items-center">
          <span className="text-sm text-muted-foreground">Open Findings</span>
          <span className="text-2xl font-bold text-primary">{openFindings.toLocaleString()}</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-sm text-muted-foreground">Affected Assets</span>
          <span className="text-lg font-semibold text-foreground">{affectedAssets.toLocaleString()}</span>
        </div>
      </div>
      <ResponsiveContainer width="100%" height={60}>
        <BarChart data={chartData}>
          <Bar dataKey="value" radius={[4, 4, 0, 0]}>
            {chartData.map((_, index) => (
              <Cell key={`cell-${index}`} fill="hsl(var(--primary))" opacity={0.3 + (index * 0.7) / chartData.length} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

interface OverviewCardsProps {
  data: {
    total: { openFindings: number; assets: number };
    weaponized: { openFindings: number; assets: number };
    ransomware: { openFindings: number; assets: number };
    trending: { openFindings: number; assets: number };
  };
}

export function OverviewCards({ data }: OverviewCardsProps) {
  const cards = [
    {
      title: "Total Findings",
      openFindings: data.total.openFindings,
      affectedAssets: data.total.assets,
      chartData: [{ value: 50 }, { value: 80 }, { value: 65 }, { value: 90 }, { value: 75 }],
    },
    {
      title: "Weaponized Findings",
      openFindings: data.weaponized.openFindings,
      affectedAssets: data.weaponized.assets,
      chartData: [{ value: 40 }, { value: 60 }, { value: 55 }, { value: 70 }, { value: 65 }],
    },
    {
      title: "Ransomware Findings",
      openFindings: data.ransomware.openFindings,
      affectedAssets: data.ransomware.assets,
      chartData: [{ value: 30 }, { value: 45 }, { value: 40 }, { value: 50 }, { value: 48 }],
    },
    {
      title: "Trending Vulnerabilities",
      openFindings: data.trending.openFindings,
      affectedAssets: data.trending.assets,
      chartData: [{ value: 60 }, { value: 70 }, { value: 85 }, { value: 80 }, { value: 90 }],
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {cards.map((card, index) => (
        <OverviewCard key={index} {...card} />
      ))}
    </div>
  );
}
