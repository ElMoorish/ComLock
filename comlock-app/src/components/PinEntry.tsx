import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./PinEntry.css";

interface UnlockResult {
    success: boolean;
    is_decoy: boolean;
    reason: string;
}

interface PinEntryProps {
    mode: "unlock" | "setup" | "confirm";
    onSuccess?: (result?: UnlockResult) => void;
    onCancel?: () => void;
    setupPin?: string; // For confirm mode
}

export function PinEntry({ mode, onSuccess, onCancel, setupPin }: PinEntryProps) {
    const [pin, setPin] = useState("");
    const [error, setError] = useState("");
    const [attempts, setAttempts] = useState<number | null>(null);
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        if (mode === "unlock") {
            checkAttempts();
        }
    }, [mode]);

    const checkAttempts = async () => {
        try {
            const status: any = await invoke("get_security_status");
            if (status.max_failed_attempts > 0) {
                setAttempts(status.max_failed_attempts - status.failed_attempts);
            }
        } catch (e) {
            console.error("Failed to get security status", e);
        }
    };

    const handleNumberClick = (num: number) => {
        if (pin.length < 8) {
            setPin((prev) => prev + num);
            setError("");
        }
    };

    const handleBackspace = () => {
        setPin((prev) => prev.slice(0, -1));
        setError("");
    };

    const clearPin = () => {
        setPin("");
        setError("");
    };

    const handleSubmit = async () => {
        if (pin.length < 4) {
            setError("PIN must be at least 4 digits");
            return;
        }

        setLoading(true);

        try {
            if (mode === "unlock") {
                const result = await invoke<UnlockResult>("verify_unlock", { pin });
                setLoading(false);
                if (result.success) {
                    onSuccess?.(result);
                } else {
                    // Should not happen if success is true, but handle logic
                }
            } else if (mode === "setup") {
                setLoading(false);
                onSuccess?.({ success: true, is_decoy: false, reason: pin }); // Return PIN as reason
            } else if (mode === "confirm") {
                setLoading(false);
                if (pin === setupPin) {
                    onSuccess?.();
                } else {
                    setError("PINs do not match");
                    setPin("");
                }
            }
        } catch (err: any) {
            setLoading(false);
            setError(err as string);
            setPin("");
            checkAttempts();
        }
    };

    return (
        <div className="pin-entry-container">
            <div className="pin-header">
                <h2>
                    {mode === "unlock" && "SECURITY LOCK"}
                    {mode === "setup" && "SET NEW PIN"}
                    {mode === "confirm" && "CONFIRM PIN"}
                </h2>
                <p className="pin-subtitle">
                    {mode === "unlock" && "Enter authentication code"}
                    {mode === "setup" && "Create a secure access code"}
                    {mode === "confirm" && "Re-enter to confirm"}
                </p>
            </div>

            <div className="pin-display">
                {pin.split("").map((_, i) => (
                    <span key={i} className="pin-dot active">●</span>
                ))}
                {Array(Math.max(0, 4 - pin.length)).fill(0).map((_, i) => (
                    <span key={`empty-${i}`} className="pin-dot">○</span>
                ))}
            </div>

            {error && <div className="pin-error">{error}</div>}

            {attempts !== null && mode === "unlock" && (
                <div className="pin-attempts">
                    {attempts} attempts remaining
                </div>
            )}

            <div className="pin-pad">
                {[1, 2, 3, 4, 5, 6, 7, 8, 9].map((num) => (
                    <button
                        key={num}
                        className="pin-btn"
                        onClick={() => handleNumberClick(num)}
                        disabled={loading}
                    >
                        {num}
                    </button>
                ))}
                <button
                    className="pin-btn pin-action"
                    onClick={clearPin}
                    disabled={loading || pin.length === 0}
                >
                    C
                </button>
                <button
                    className="pin-btn"
                    onClick={() => handleNumberClick(0)}
                    disabled={loading}
                >
                    0
                </button>
                <button
                    className="pin-btn pin-action"
                    onClick={handleBackspace}
                    disabled={loading || pin.length === 0}
                >
                    ⌫
                </button>
            </div>

            <div className="pin-actions">
                {onCancel && (
                    <button className="cancel-btn" onClick={onCancel} disabled={loading}>
                        CANCEL
                    </button>
                )}
                <button
                    className="submit-btn"
                    onClick={handleSubmit}
                    disabled={loading || pin.length < 4}
                >
                    {loading ? "VERIFYING..." : "ENTER"}
                </button>
            </div>
        </div>
    );
}
