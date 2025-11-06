import { createContext, useContext, useEffect, useState } from "react";

type Theme = "dark" | "light";
interface ThemeContext { theme: Theme; setTheme: (t: Theme) => void; }

const ThemeCtx = createContext<ThemeContext | undefined>(undefined);

export function ThemeProvider({ children }: any) {
  const [theme, setTheme] = useState<Theme>("dark");
  useEffect(() => {
    document.documentElement.classList.remove("light", "dark");
    document.documentElement.classList.add(theme);
  }, [theme]);
  return <ThemeCtx.Provider value={{ theme, setTheme }}>{children}</ThemeCtx.Provider>;
}

export const useTheme = () => {
  const ctx = useContext(ThemeCtx);
  if (!ctx) throw new Error("useTheme must be inside ThemeProvider");
  return ctx;
};
