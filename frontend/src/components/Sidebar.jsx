import React from "react";
import UploadFile from "./UploadFile";

const Sidebar = ({ setData }) => {
  return (
    <div className="w-64 bg-slate-800 text-white flex flex-col p-4">
      <h2 className="text-xl font-semibold mb-4">📁 Upload Data</h2>
      <UploadFile setData={setData} />
    </div>
  );
};

export default Sidebar;
