import React from "react";

export default function GaugeCard({ title, value, max }: any) {
  const ratio = Math.min(Number(value) / max, 1);
  const rotation = 180 * ratio;
  return (
    <div className="bg-gray-900 rounded-xl p-4 text-center shadow flex flex-col items-center">
      <h3 className="mb-2">{title}</h3>
      <div className="relative w-24 h-12 overflow-hidden">
        <div
          className="absolute w-24 h-24 border-[10px] border-yellow-400 rounded-full border-b-transparent border-r-transparent"
          style={{ transform: `rotate(${rotation}deg)` }}
        />
      </div>
      <p className="text-2xl font-bold mt-3">{value}</p>
    </div>
  );
}
