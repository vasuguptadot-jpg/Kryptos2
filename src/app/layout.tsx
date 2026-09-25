import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = {
  title: "Kryptos Broker",
  description: "Central secret broker. Secrets are used server-side only and are never exposed.",
  robots: { index: false, follow: false }
};

export const viewport: Viewport = {
  themeColor: "#0b0e14"
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, background: "#0b0e14", color: "#e6e9ef", fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif" }}>
        {children}
      </body>
    </html>
  );
}
