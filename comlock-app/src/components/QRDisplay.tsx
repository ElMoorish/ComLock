import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface QrExchangeResult {
    exchange_id: string;
    qr_payload: string;
}

interface QRDisplayProps {
    onScanReady?: (exchangeId: string) => void;
    onClose?: () => void;
}

/**
 * QRDisplay Component
 * 
 * Generates an ephemeral keypair and displays a QR code for in-person
 * key exchange. The QR expires after 5 minutes.
 */
export function QRDisplay({ onScanReady, onClose }: QRDisplayProps) {
    const [qrPayload, setQrPayload] = useState<string>("");
    const [countdown, setCountdown] = useState(300); // 5 minutes
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string>("");

    // Generate QR payload on mount
    useEffect(() => {
        generateQr();
    }, []);

    // Countdown timer
    useEffect(() => {
        if (countdown <= 0) {
            setError("QR code expired. Generate a new one.");
            return;
        }

        const timer = setInterval(() => {
            setCountdown((prev) => prev - 1);
        }, 1000);

        return () => clearInterval(timer);
    }, [countdown]);

    const generateQr = async () => {
        setLoading(true);
        setError("");
        setCountdown(300);

        try {
            const result = await invoke<QrExchangeResult>("generate_qr_payload");
            setQrPayload(result.qr_payload);
            onScanReady?.(result.exchange_id);
        } catch (err) {
            setError(err as string);
        }

        setLoading(false);
    };

    // Format countdown as MM:SS
    const formatTime = (seconds: number) => {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}:${secs.toString().padStart(2, "0")}`;
    };

    // Generate simple ASCII QR placeholder (real QR would use a library)
    const renderQrPlaceholder = () => {
        if (!qrPayload) return null;

        // In production, use qrcode-generator or similar
        return (
            <div className="qr-code-container">
                <div className="qr-code-placeholder">
                    <div className="qr-pattern">
                        {/* ASCII art QR pattern for demo */}
                        <pre className="mono" style={{ fontSize: "6px", lineHeight: "6px" }}>
                            {`█▀▀▀▀▀█ ▄▀▄▀▄ █▀▀▀▀▀█
█ ███ █ ▄▀ ▄▄ █ ███ █
█ ▀▀▀ █ █▄▀▄█ █ ▀▀▀ █
▀▀▀▀▀▀▀ ▀ █ ▀ ▀▀▀▀▀▀▀
▀▄█▄▄▀▀▄▀▀█▀▄▄▀▀▀▀█▀▄
█▄▀█▄ ▀ ▀ ▀▄▀▀▄█▄█ ▄█
▀ ▀ ▀▀▀▀█▀█ ▀▀▀▀▀▀▀▀▀
█▀▀▀▀▀█ ▀▄█ █▀ ▄ ▄ ▀█
█ ███ █ ▄▀▄▄▀▀▄▀▄ ▄ ▄
█ ▀▀▀ █ ▀ ▀▀ ▀▀▀ █▀▀█
▀▀▀▀▀▀▀ ▀▀▀▀ ▀ ▀▀▀▀▀▀`}
                        </pre>
                    </div>
                </div>
                <p className="qr-hint text-muted">
                    Ask your contact to scan this code
                </p>
            </div>
        );
    };

    return (
        <div className="qr-display">
            <div className="qr-header">
                <h3 className="mono">Share Your Code</h3>
                {onClose && (
                    <button className="close-btn" onClick={onClose}>
                        ✕
                    </button>
                )}
            </div>

            {loading && (
                <div className="qr-loading">
                    <div className="spinner" />
                    <p>Generating ephemeral keys...</p>
                </div>
            )}

            {error && (
                <div className="qr-error">
                    <p className="text-amber">{error}</p>
                    <button className="btn btn-outline" onClick={generateQr}>
                        Generate New Code
                    </button>
                </div>
            )}

            {!loading && !error && (
                <>
                    {renderQrPlaceholder()}

                    <div className="qr-countdown">
                        <div className={`countdown ${countdown < 60 ? "warning" : ""}`}>
                            <span className="countdown-icon">⏱</span>
                            <span className="countdown-time">{formatTime(countdown)}</span>
                        </div>
                        <p className="text-muted">Expires in</p>
                    </div>

                    <button className="btn btn-outline btn-block" onClick={generateQr}>
                        ↻ Generate New Code
                    </button>
                </>
            )}

            <div className="qr-security-note">
                <span>🔒</span>
                <span className="text-muted">
                    Keys are ephemeral and never stored on servers
                </span>
            </div>
        </div>
    );
}

export default QRDisplay;
