import React from "react";
import { Routes, Route, Link } from "react-router-dom";
import UploadPage from "./pages/Upload";
import DashboardPage from "./pages/Dashboard";
import FindingsPage from "./pages/Findings";
import { DataProvider } from "./hooks/DataContext";

export default function App() {
  return (
    <DataProvider>
      <div className="min-h-screen bg-slate-900 text-slate-100">
        <header className="bg-slate-800 p-4 shadow-md">
          <div className="container mx-auto flex items-center justify-between">
            <h1 className="text-xl font-bold">InfoX — Vulnerability Accelerator</h1>
            <nav className="space-x-4">
              <Link className="hover:underline" to="/">Upload</Link>
              <Link className="hover:underline" to="/dashboard">Dashboard</Link>
              <Link className="hover:underline" to="/findings">Findings</Link>
            </nav>
          </div>
        </header>

        <main className="container mx-auto p-6">
          <Routes>
            <Route path="/" element={<UploadPage />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/findings" element={<FindingsPage />} />
          </Routes>
        </main>
      </div>
    </DataProvider>
  );
}
