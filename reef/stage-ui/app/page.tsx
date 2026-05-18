import { HeroStrip } from "@/app/components/HeroStrip";
import { FleetStatusPanel } from "@/app/components/FleetStatusPanel";
import { RecentDecisionsFeed } from "@/app/components/RecentDecisionsFeed";
import { AttackPackCatalog } from "@/app/components/AttackPackCatalog";
import { MCPRegistryBeat } from "@/app/components/MCPRegistryBeat";
import { RIAPanel } from "@/app/components/RIAPanel";
import { AttackPlayground } from "@/app/components/AttackPlayground";
import { ComplianceWall } from "@/app/components/ComplianceWall";
import { Footer } from "@/app/components/Footer";

/**
 * Public Safety Page — what judges hit at http://localhost:3000.
 *
 * Eight sections top-to-bottom (per A-11 task spec §2):
 *   1. Hero strip — Reef wordmark + dinner sentence + 3 context chips
 *   2. Live fleet status — FleetGrid (49 dots) + counters + signed bundle
 *   3. MCP supply-chain block beat — live Atlas /verify against poisoned bind
 *   4. Recent decisions feed — last 20 events from policy-bus /audit/tail
 *   5. DAST-A attack pack catalog — OWASP + MITRE + blocked status
 *   6. RIA panel — tier headline, premium range, verbatim disclaimers, download
 *   7. Compliance wall — honest 3-state coverage matrix
 *   8. Attack playground — paste a poisoned email OR iframe the victim
 *   + Footer — GitHub repo, MIT badge, last-deploy timestamp
 *
 * Every panel handles its own service-offline degradation — single-service
 * outages render an inline "service offline" badge, never crash the page.
 */
export default function PublicSafetyPage() {
  return (
    <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-10 py-8 lg:py-12 space-y-8">
      <HeroStrip />

      <FleetStatusPanel />

      {/* MCPRegistryBeat is the PRIMARY HEADLINE — Batch D R-D5 restructured
       *  it into a one-big-punch layout (60% main + 25% side rail + 15%
       *  footer). It now takes a full row so the BIND DENIED glyph has the
       *  visual mass POV-3 #3 asked for. RecentDecisionsFeed sits below. */}
      <MCPRegistryBeat />

      <RecentDecisionsFeed />

      <AttackPackCatalog />

      <RIAPanel />

      <ComplianceWall />

      <AttackPlayground />

      <Footer />
    </main>
  );
}
