import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

interface GaugeChartProps {
  value: number;
  title: string;
  maxValue?: number;
}

const getRiskLevel = (value: number) => {
  if (value < 400) return { label: "Critical Risk", color: "hsl(var(--severity-critical))" };
  if (value < 650) return { label: "High Risk", color: "hsl(var(--severity-high))" };
  if (value < 850) return { label: "Medium Risk", color: "hsl(var(--severity-medium))" };
  return { label: "Low Risk", color: "hsl(var(--severity-low))" };
};

export function GaugeChart({ value, title, maxValue = 1000 }: GaugeChartProps) {
  const percentage = (value / maxValue) * 100;
  const risk = getRiskLevel(value);

  const data = [
    { name: "value", value: percentage },
    { name: "empty", value: 100 - percentage },
  ];

  return (
    <div className="flex flex-col items-center justify-center p-6 bg-card rounded-lg border border-border">
      <h3 className="text-lg font-semibold mb-2 text-card-foreground">{title}</h3>
      <div className="relative w-48 h-48">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              startAngle={180}
              endAngle={0}
              innerRadius={60}
              outerRadius={80}
              dataKey="value"
              stroke="none"
            >
              <Cell fill={risk.color} />
              <Cell fill="hsl(var(--muted))" />
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-4xl font-bold text-foreground">{value}</div>
          <div className="text-sm text-muted-foreground">/ {maxValue}</div>
        </div>
      </div>
      <div
        className="mt-4 px-4 py-2 rounded-full font-semibold text-sm"
        style={{ backgroundColor: risk.color, color: "white" }}
      >
        {risk.label}
      </div>
    </div>
  );
}
