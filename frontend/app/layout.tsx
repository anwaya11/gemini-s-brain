import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });

export const metadata: Metadata = {
  title: "Chimera SOC — Autonomous Security Operations Center",
  description:
    "Real-time security incident triage, risk-weighted autonomy, and attack-graph visualization powered by AI.",
  keywords: ["SOC", "security", "SIEM", "MITRE ATT&CK", "threat intelligence", "incident response"],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={inter.variable}>
      <body className={inter.className}>{children}</body>
    </html>
  );
}
