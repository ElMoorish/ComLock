"use client";

import { motion } from "framer-motion";
import { Terminal } from "lucide-react";

const typingContainer = {
    hidden: { opacity: 0 },
    show: {
        opacity: 1,
        transition: {
            staggerChildren: 0.08,
        },
    },
};

const typingLetter = {
    hidden: { opacity: 0, y: 5 },
    show: { opacity: 1, y: 0 },
};

export default function HeroTerminal() {
    const text = "COMLOCK SECURE MESSAGING";
    const subtext = [
        "> Init Loopix Protocol...",
        "> Generating ML-KEM Keys...",
        "> Establishing Secure Channel...",
        "> Connection: ENCRYPTED [Verified]"
    ];

    return (
        <div className="w-full max-w-4xl mx-auto my-12 relative group">
            {/* Terminal Window */}
            <div className="bg-panel border border-border-dim rounded-lg overflow-hidden shadow-2xl">
                {/* Header Bar */}
                <div className="bg-border-dim/30 px-4 py-2 flex items-center gap-2 border-b border-border-dim">
                    <div className="flex gap-2">
                        <div className="w-3 h-3 rounded-full bg-red-500/80" />
                        <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                        <div className="w-3 h-3 rounded-full bg-green-500/80" />
                    </div>
                    <div className="ml-4 text-xs text-gray-500 font-mono flex items-center gap-2">
                        <Terminal size={12} />
                        <span>bash — 80x24</span>
                    </div>
                </div>

                {/* Content Body */}
                <div className="p-6 md:p-10 font-mono text-sm md:text-base min-h-[300px]">
                    {/* Main Headline Typing */}
                    <motion.h1
                        className="text-2xl md:text-4xl font-bold text-text-primary mb-6 flex flex-wrap gap-1"
                        variants={typingContainer}
                        initial="hidden"
                        animate="show"
                    >
                        {text.split("").map((char, i) => (
                            <motion.span key={i} variants={typingLetter}>
                                {char}
                            </motion.span>
                        ))}
                        <motion.div
                            className="w-3 h-8 bg-cursor ml-1"
                            animate={{ opacity: [1, 0] }}
                            transition={{ repeat: Infinity, duration: 0.8 }}
                        />
                    </motion.h1>

                    {/* Boot Logs */}
                    <div className="space-y-2 text-gray-400">
                        {subtext.map((line, i) => (
                            <motion.div
                                key={i}
                                initial={{ opacity: 0, x: -10 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ delay: 2 + (i * 0.5) }} // Start after headline
                            >
                                <span className={line.includes("Verified") ? "text-text-success" : ""}>
                                    {line}
                                </span>
                            </motion.div>
                        ))}
                    </div>

                    {/* Interactive Prompt */}
                    <motion.div
                        className="mt-8 flex items-center gap-2 text-text-success"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 4.5 }}
                    >
                        <span>$</span>
                        <span className="text-text-primary">ready_to_deploy</span>
                        <div className="w-2 h-4 bg-text-success animate-pulse" />
                    </motion.div>
                </div>
            </div>

            {/* Decorative Glow */}
            <div className="absolute inset-0 bg-text-highlight/5 blur-3xl -z-10 rounded-full opacity-20" />
        </div>
    );
}
