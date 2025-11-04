import React, { useState } from "react";
import "./App.css";
import Sidebar from "./components/Sidebar";
import Dashboard from "./components/Dashboard";

function App() {
  const [data, setData] = useState(null); // store uploaded CSV data

  return (
    <div className="flex h-screen bg-gray-100">
      <Sidebar setData={setData} />
      <div className="flex-1 overflow-auto p-6">
        <Dashboard data={data} />
      </div>
    </div>
  );
}

export default App;
