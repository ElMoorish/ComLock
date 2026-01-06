import Link from "next/link";
import { Download, AlertTriangle } from "lucide-react";
import { getLatestRelease, formatBytes } from "@/lib/github";

export default async function ReleaseBadge() {
    const release = await getLatestRelease();

    if (!release) {
        return (
            <div className="inline-flex flex-col gap-2">
                <Link
                    href="https://github.com/ElMoorish/ComLock/releases"
                    className="flex items-center gap-3 px-8 py-4 bg-panel border-2 border-red-500/50 text-red-400 font-mono hover:bg-red-900/10 transition-colors group"
                >
                    <AlertTriangle size={24} />
                    <div className="flex flex-col items-start">
                        <span className="font-bold">CONNECTION_ERR</span>
                        <span className="text-xs opacity-70">Manual Download Required</span>
                    </div>
                </Link>
            </div>
        );
    }

    const apk = release.assets.apk;

    // Use fallback URL if no APK found in latest release
    const downloadUrl = apk ? apk.download_url : release.html_url;
    const sizeLabel = apk ? formatBytes(apk.size) : "GITHUB";

    return (
        <div className="flex flex-col items-center gap-4">
            <Link
                href={downloadUrl}
                className="relative flex items-center gap-4 px-8 py-4 bg-text-accent text-black font-mono font-bold tracking-tight hover:brightness-110 active:scale-95 transition-all group overflow-hidden"
            >
                {/* Scanlines Effect */}
                <div className="absolute inset-0 bg-[url('/scanlines.png')] opacity-10 pointer-events-none" />

                <Download className="group-hover:animate-bounce" />
                <div className="flex flex-col items-start">
                    <span className="text-lg">INITIATE DOWNLOAD</span>
                    <div className="flex items-center gap-2 text-xs opacity-80 font-normal">
                        <span>v{release.tag_name}</span>
                        <span>•</span>
                        <span>{sizeLabel}</span>
                    </div>
                </div>

                {/* Pixel Corners */}
                <div className="absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-black" />
                <div className="absolute top-0 right-0 w-2 h-2 border-t-2 border-r-2 border-black" />
                <div className="absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 border-black" />
                <div className="absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-black" />
            </Link>

            <div className="text-[10px] text-gray-500 font-mono flex gap-4">
                <span>SHA256: VALID</span>
                <span>SIG: VERIFIED</span>
            </div>
        </div>
    );
}
