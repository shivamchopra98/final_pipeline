import React, { createContext, useContext, useState } from "react";

type RecordAny = Record<string, any>;

interface DataContextShape {
  data: RecordAny[];
  setData: (d: RecordAny[]) => void;
  csv?: string | null;
  setCsv: (s: string | null) => void;
  scanner?: string | null;
  setScanner: (s: string | null) => void;
}

const DataContext = createContext<DataContextShape | undefined>(undefined);

export const DataProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [data, setData] = useState<RecordAny[]>([]);
  const [csv, setCsv] = useState<string | null>(null);
  const [scanner, setScanner] = useState<string | null>(null);

  return (
    <DataContext.Provider value={{ data, setData, csv, setCsv, scanner, setScanner }}>
      {children}
    </DataContext.Provider>
  );
};

export const useData = () => {
  const ctx = useContext(DataContext);
  if (!ctx) throw new Error("useData must be used inside DataProvider");
  return ctx;
};
