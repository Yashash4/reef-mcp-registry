import type { Metadata } from "next";
import { Inter, JetBrains_Mono, Instrument_Serif } from "next/font/google";
import "./globals.css";
import { QueryProvider } from "@/app/lib/providers/query-provider";
import { DemoModeBanner } from "@/app/components/DemoModeBanner";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});
const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains-mono",
  display: "swap",
});
const instrumentSerif = Instrument_Serif({
  subsets: ["latin"],
  weight: "400",
  style: ["italic", "normal"],
  variable: "--font-instrument-serif",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Reef — Public Safety Page",
  description:
    "The signed supply chain for MCP servers + the only AI firewall that outputs an underwriter-scorable evidence artifact. Live fleet, signed-policy hash, blocked-attack feed.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable} ${instrumentSerif.variable}`}
    >
      <body className="bg-bg text-text min-h-screen antialiased">
        <QueryProvider>
          <DemoModeBanner />
          {children}
        </QueryProvider>
      </body>
    </html>
  );
}
