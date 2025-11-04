import React from "react";
import Papa from "papaparse";

const UploadFile = ({ setData }) => {
  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    Papa.parse(file, {
      header: true,
      skipEmptyLines: true,
      complete: (results) => {
        setData(results.data);
      },
    });
  };

  return (
    <div className="bg-slate-700 p-3 rounded-lg">
      <input
        type="file"
        accept=".csv,.txt"
        onChange={handleFileUpload}
        className="block w-full text-sm text-gray-200 border border-slate-500 rounded-md cursor-pointer p-2 bg-slate-600 hover:bg-slate-500"
      />
    </div>
  );
};

export default UploadFile;
