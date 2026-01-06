import HeroTerminal from "@/components/hero-terminal";
import FeatureGrid from "@/components/feature-grid";
import ReleaseBadge from "@/components/release-badge";
import Footer from "@/components/footer";

export default function Home() {
  return (
    <main className="min-h-screen bg-terminal flex flex-col items-center overflow-x-hidden selection:bg-text-accent selection:text-terminal">
      {/* Grid Background Pattern */}
      <div className="fixed inset-0 z-0 opacity-[0.03] pointer-events-none"
        style={{ backgroundImage: 'linear-gradient(#333 1px, transparent 1px), linear-gradient(90deg, #333 1px, transparent 1px)', backgroundSize: '40px 40px' }}
      />

      <div className="relative z-10 w-full flex flex-col items-center">

        {/* Section 1: Hero */}
        <HeroTerminal />

        {/* Section 2: Download Call to Action */}
        <div className="my-12">
          <ReleaseBadge />
        </div>

        {/* Section 3: Features */}
        <section className="w-full px-4 mb-24">
          <div className="max-w-6xl mx-auto mb-8 border-b border-border-dim pb-2 flex items-center justify-between">
            <h2 className="text-xl font-mono text-text-primary flex items-center gap-2">
              <div className="w-2 h-2 bg-text-success rounded-full animate-pulse" />
              SYSTEM ARCHITECTURE
            </h2>
            <span className="text-xs text-gray-600 font-mono">CONFIDENTIALITY: MAX</span>
          </div>
          <FeatureGrid />
        </section>

        <Footer />
      </div>
    </main>
  );
}
