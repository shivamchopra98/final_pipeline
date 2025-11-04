import React from "react";

const VulnerabilitiesTable = ({ data }) => (
  <div className="bg-white p-4 rounded-lg shadow-md overflow-auto">
    <h2 className="text-lg font-semibold mb-3">🧾 Vulnerability Findings</h2>
    <table className="min-w-full text-sm border-collapse border border-gray-200">
      <thead className="bg-gray-100">
        <tr>
          {Object.keys(data[0]).slice(0, 6).map((col) => (
            <th key={col} className="px-4 py-2 text-left border border-gray-200">
              {col}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {data.slice(0, 20).map((row, i) => (
          <tr key={i} className="hover:bg-gray-50 border-t">
            {Object.keys(data[0]).slice(0, 6).map((col) => (
              <td key={col} className="px-4 py-2 border border-gray-200">
                {row[col]}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

export default VulnerabilitiesTable;
