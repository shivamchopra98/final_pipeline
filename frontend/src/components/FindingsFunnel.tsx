// import React from "react";

// const FunnelRow: React.FC<{ label: string; color: string; count: number; assets?: number; pct?: number }> = ({
//   label,
//   color,
//   count,
//   assets = 0,
//   pct = 0,
// }) => (
//   <div
//     className="rounded-xl p-6 mb-6 flex items-center justify-between shadow-lg"
//     style={{ background: color }}
//   >
//     <div>
//       <div className="text-2xl font-bold text-white">{label}</div>
//       <div className="text-sm text-white/80 mt-1">{pct}% of findings</div>
//     </div>
//     <div className="text-right">
//       <div className="text-4xl font-extrabold text-white">{count.toLocaleString()}</div>
//       <div className="text-sm text-white/80 mt-1">{assets} assets</div>
//     </div>
//   </div>
// );

// const FindingsFunnel: React.FC<{ data: any[] }> = ({ data }) => {
//   const severity = (d: any) => ((d.ibm_attack_complexity || d.severity || "").toString() || "Info").toLowerCase();
//   const totals = {
//     critical: data.filter((d) => severity(d) === "critical").length,
//     high: data.filter((d) => severity(d) === "high").length,
//     medium: data.filter((d) => severity(d) === "medium").length,
//     low: data.filter((d) => severity(d) === "low").length,
//   };
//   const totalFindings = data.length || 1;
//   const assetsFor = (_count: number) => Math.round(_count * 0.5);

//   return (
//     <div>
//       <h2 className="text-2xl font-bold mb-6">Open Findings by Severity</h2>
//       <FunnelRow label="Critical" color="#e03b3b" count={totals.critical} assets={assetsFor(totals.critical)} pct={Math.round((totals.critical / totalFindings) * 100)} />
//       <FunnelRow label="High" color="#ff8a3d" count={totals.high} assets={assetsFor(totals.high)} pct={Math.round((totals.high / totalFindings) * 100)} />
//       <FunnelRow label="Medium" color="#ffd63d" count={totals.medium} assets={assetsFor(totals.medium)} pct={Math.round((totals.medium / totalFindings) * 100)} />
//       <FunnelRow label="Low" color="#a6e86a" count={totals.low} assets={assetsFor(totals.low)} pct={Math.round((totals.low / totalFindings) * 100)} />
//     </div>
//   );
// };

// export default FindingsFunnel;
