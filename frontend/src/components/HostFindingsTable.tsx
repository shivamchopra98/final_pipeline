// import React, { useState } from "react";
// import { Modal } from "./Modal";

// const HostFindingsTable: React.FC<{ data: any[] }> = ({ data }) => {
//   const [selected, setSelected] = useState<any | null>(null);
//   if (!data || data.length === 0) return <div className="text-gray-400">No findings found.</div>;

//   const cols = ["cve_id", "date_updated", "ibm_affected_products", "ibm_attack_complexity", "ibm_attack_vector", "ibm_availability_impact"];

//   return (
//     <div className="bg-[#0b1320] rounded-xl p-4 text-white shadow-lg">
//       <div className="overflow-auto max-h-[70vh]">
//         <table className="min-w-full">
//           <thead className="sticky top-0 bg-[#0b1320]">
//             <tr>
//               {cols.map((c) => (
//                 <th key={c} className="text-left p-3 text-sm text-gray-300">
//                   {c.replace(/_/g, " ").toUpperCase()}
//                 </th>
//               ))}
//               <th className="p-3 text-sm text-gray-300">ACTION</th>
//             </tr>
//           </thead>
//           <tbody>
//             {data.map((row, i) => (
//               <tr
//                 key={i}
//                 className="border-b border-gray-800 hover:bg-gray-900 cursor-pointer"
//                 onClick={() => setSelected(row)}
//               >
//                 {cols.map((c) => (
//                   <td key={c} className="p-3 text-sm text-gray-200 truncate max-w-[220px]">
//                     {typeof row[c] === "object" ? JSON.stringify(row[c]).slice(0, 100) : row[c] ?? "-"}
//                   </td>
//                 ))}
//                 <td className="p-3 text-sm text-blue-400">View</td>
//               </tr>
//             ))}
//           </tbody>
//         </table>
//       </div>

//       {selected && (
//         <Modal onClose={() => setSelected(null)}>
//           <div className="space-y-3">
//             <h3 className="text-xl font-bold">{selected.cve_id}</h3>
//             <div className="text-sm text-gray-400">
//               Products: {selected.ibm_affected_products || "N/A"}
//             </div>
//             <div className="text-sm text-gray-400">
//               Complexity: {selected.ibm_attack_complexity || "N/A"}
//             </div>
//             <div className="text-sm text-gray-400">
//               Vector: {selected.ibm_attack_vector || "N/A"}
//             </div>
//             <div className="text-sm text-gray-400">
//               Impact: {selected.ibm_availability_impact || "N/A"}
//             </div>
//             <p className="pt-3 text-sm text-gray-300">
//               {Array.isArray(selected.descriptions)
//                 ? selected.descriptions.join("\n\n")
//                 : selected.descriptions || "No description"}
//             </p>
//           </div>
//         </Modal>
//       )}
//     </div>
//   );
// };

// export default HostFindingsTable;
