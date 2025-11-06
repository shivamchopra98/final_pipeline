import React from "react";

export default function TableView({ rows }: any) {
  if (!rows.length) return <p>No data available</p>;
  const headers = Object.keys(rows[0]);
  return (
    <div className="overflow-x-auto border border-gray-700 rounded-xl">
      <table className="min-w-full text-sm text-gray-200">
        <thead className="bg-gray-800">
          <tr>{headers.map(h => <th key={h} className="px-3 py-2">{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r: any, i: number) => (
            <tr key={i} className="border-t border-gray-700 hover:bg-gray-800/60">
              {headers.map(h => (
                <td key={h} className="px-3 py-1 truncate max-w-xs">{String(r[h] ?? "")}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
