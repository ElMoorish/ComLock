"use client";

import { motion } from "framer-motion";
import { Server, ShieldCheck, Network, Lock, Download, ChevronRight } from "lucide-react";

// --- Visualizers ---

function MixnetVisual() {
    return (
        <div className="relative h-48 w-full bg-black/20 rounded border border-border-dim/50 overflow-hidden flex items-center justify-center">
            <div className="grid grid-cols-3 gap-8">
                {[...Array(6)].map((_, i) => (
                    <div key={i} className="relative group">
                        <Server className="text-border-dim group-hover:text-text-highlight transition-colors duration-500" size={24} />
                        {/* Connection Lines (Simulated) */}
                        <div className="absolute top-1/2 left-full w-8 h-[1px] bg-border-dim/30" />
                    </div>
                ))}
            </div>

            {/* Animated Packets */}
            {[...Array(3)].map((_, i) => (
                <motion.div
                    key={i}
                    className="absolute w-2 h-2 bg-text-highlight rounded-full"
                    animate={{
                        x: [-50, 200],
                        y: [Math.sin(i) * 20, Math.cos(i) * -20],
                        opacity: [0, 1, 0]
                    }}
                    transition={{
                        duration: 3,
                        repeat: Infinity,
                        delay: i * 0.8,
                        ease: "linear"
                    }}
                />
            ))}

            <div className="absolute bottom-2 right-2 text-[10px] text-gray-500 font-mono">LOOPIX_V3</div>
        </div>
    );
}

function QuantumShield() {
    return (
        <div className="relative h-48 w-full bg-black/20 rounded border border-border-dim/50 flex items-center justify-center perspective-500 overflow-hidden">
            <ShieldCheck className="text-text-success z-10" size={48} />

            {/* Rotating Lattice */}
            <motion.div
                className="absolute inset-0 grid grid-cols-6 grid-rows-6 gap-2 opacity-20"
                animate={{ rotate: 360, scale: [1, 1.2, 1] }}
                transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
            >
                {[...Array(36)].map((_, i) => (
                    <div key={i} className="w-1 h-1 bg-text-success rounded-full" />
                ))}
            </motion.div>

            <div className="absolute bottom-2 right-2 text-[10px] text-gray-500 font-mono">ML-KEM-1024</div>
        </div>
    );
}

// --- Main Grid ---

export default function FeatureGrid() {
    const features = [
        {
            title: "Loopix Mixnet",
            description: "Traffic analysis resistance via Poisson-distributed packet mixing.",
            visual: <MixnetVisual />,
            icon: Network
        },
        {
            title: "Post-Quantum",
            description: "End-to-end encryption secured by ML-KEM-1024.",
            visual: <QuantumShield />,
            icon: Lock
        },
        {
            title: "Panic Layer",
            description: "Duress PINs and Dead Man's Switch for plausible deniability.",
            visual: (
                <div className="h-48 flex items-center justify-center border border-border-dim/50 rounded bg-red-900/5">
                    <div className="text-red-500 font-mono text-center">
                        <div className="text-4xl mb-2">⚠️</div>
                        <div>DURESS MODE</div>
                        <div className="text-xs opacity-50">DATA WIPED</div>
                    </div>
                </div>
            ),
            icon: ShieldCheck
        }
    ];

    return (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full max-w-6xl mx-auto p-4">
            {features.map((f, i) => (
                <motion.div
                    key={i}
                    className="bg-panel border border-border-dim p-1 rounded-xl hover:border-text-highlight/50 transition-colors"
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.2 }}
                    viewport={{ once: true }}
                >
                    <div className="h-full bg-terminal rounded-lg overflow-hidden flex flex-col">
                        {/* Visual Header */}
                        <div className="p-2">
                            {f.visual}
                        </div>

                        {/* Content */}
                        <div className="p-6 flex-1 flex flex-col">
                            <div className="flex items-center gap-2 mb-3 text-text-primary">
                                <f.icon className="text-text-highlight" size={20} />
                                <h3 className="font-bold text-lg font-mono">{f.title}</h3>
                            </div>
                            <p className="text-gray-400 text-sm leading-relaxed mb-4 flex-1">
                                {f.description}
                            </p>

                            <div className="flex items-center gap-1 text-xs text-text-highlight cursor-pointer group w-fit">
                                <span>SYS_INFO</span>
                                <ChevronRight size={12} className="group-hover:translate-x-1 transition-transform" />
                            </div>
                        </div>
                    </div>
                </motion.div>
            ))}
        </div>
    );
}
