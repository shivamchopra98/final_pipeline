// import React from "react";
// import { Bar, Pie } from "react-chartjs-2";
// import { Chart as ChartJS, CategoryScale, LinearScale, ArcElement, BarElement, Tooltip, Legend } from "chart.js";

// ChartJS.register(CategoryScale, LinearScale, ArcElement, BarElement, Tooltip, Legend);

// export const BarChart = ({ data }: { data: any[] }) => {
//   const counts = {
//     High: data.filter((d) => d.ibm_attack_complexity === "High").length,
//     Medium: data.filter((d) => d.ibm_attack_complexity === "Medium").length,
//     Low: data.filter((d) => d.ibm_attack_complexity === "Low").length,
//   };

//   return (
//     <div className="bg-white dark:bg-gray-900 rounded-xl shadow p-4">
//       <h3 className="text-lg font-semibold mb-2">Attack Complexity Distribution</h3>
//       <Bar
//         data={{
//           labels: Object.keys(counts),
//           datasets: [
//             {
//               label: "Count",
//               data: Object.values(counts),
//             },
//           ],
//         }}
//       />
//     </div>
//   );
// };

// export const PieChart = ({ data }: { data: any[] }) => {
//   const impactCount = data.reduce((acc: any, cur: any) => {
//     const key = cur.ibm_availability_impact || "Unknown";
//     acc[key] = (acc[key] || 0) + 1;
//     return acc;
//   }, {});

//   return (
//     <div className="bg-white dark:bg-gray-900 rounded-xl shadow p-4">
//       <h3 className="text-lg font-semibold mb-2">Availability Impact</h3>
//       <Pie
//         data={{
//           labels: Object.keys(impactCount),
//           datasets: [
//             {
//               data: Object.values(impactCount),
//               backgroundColor: ["#FF6384", "#36A2EB", "#FFCE56", "#8BC34A"],
//             },
//           ],
//         }}
//       />
//     </div>
//   );
// };
// export default { BarChart, PieChart };