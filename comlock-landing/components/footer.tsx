export default function Footer() {
    return (
        <footer className="w-full mt-24 border-t border-border-dim bg-panel/50">
            {/* MOTD Ticker */}
            <div className="w-full bg-terminal overflow-hidden border-b border-border-dim py-2 relative">
                <div className="animate-marquee whitespace-nowrap text-xs text-text-success/70 font-mono">
                    "PRIVACY IS NECESSARY FOR AN OPEN SOCIETY IN THE ELECTRONIC AGE... WE CANNOT EXPECT GOVERNMENTS, CORPORATIONS, OR OTHER LARGE, FACELESS ORGANIZATIONS TO GRANT US PRIVACY OUT OF THEIR BENEFICENCE." — ERIC HUGHES, A CYPHERPUNK'S MANIFESTO (1993) +++ SYSTEM STATUS: ONLINE +++ NODES DETECTED: 8,492 +++ ENCRYPTION: POST-QUANTUM VERIFIED +++
                </div>

                {/* Gradient Fade Edges */}
                <div className="absolute inset-y-0 left-0 w-8 bg-gradient-to-r from-terminal to-transparent pointer-events-none" />
                <div className="absolute inset-y-0 right-0 w-8 bg-gradient-to-l from-terminal to-transparent pointer-events-none" />
            </div>

            <div className="max-w-6xl mx-auto p-8 flex flex-col md:flex-row justify-between items-center gap-6">
                <div className="text-gray-500 text-xs font-mono">
                    © 2026 COMLOCK PROJECT. NO LOGS. NO TRACKERS. NO COMPROMISE.
                </div>

                <div className="flex gap-6 text-sm font-mono text-text-primary">
                    <a href="#" className="hover:text-text-highlight transition-colors">GITHUB</a>
                    <a href="#" className="hover:text-text-highlight transition-colors">DOCS</a>
                    <a href="#" className="hover:text-text-highlight transition-colors">KEYS</a>
                </div>
            </div>
        </footer>
    );
}
