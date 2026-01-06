import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ScanResult {
    sas: string;
}

interface Contact {
    id: string;
    alias: string;
    public_key: string;
    kem_pubkey: string;
    session_id: string;
    added_at: number;
    verified: boolean;
}

interface QRScannerProps {
    exchangeId: string;
    onContactAdded?: (contact: Contact) => void;
    onClose?: () => void;
}

/**
 * QRScanner Component
 * 
 * Processes scanned QR codes, computes shared secret, displays SAS
 * for verbal confirmation, and creates verified contacts.
 */
export function QRScanner({ exchangeId, onContactAdded, onClose }: QRScannerProps) {
    const [step, setStep] = useState<"scan" | "verify" | "name" | "done">("scan");
    const [qrInput, setQrInput] = useState("");
    const [sas, setSas] = useState("");
    const [alias, setAlias] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);
    const [newContact, setNewContact] = useState<Contact | null>(null);

    // Process the scanned QR code
    const handleProcessQr = async () => {
        if (!qrInput.trim()) {
            setError("Please paste the scanned QR data");
            return;
        }

        setLoading(true);
        setError("");

        try {
            const result = await invoke<ScanResult>("process_scanned_qr", {
                exchangeId,
                qrJson: qrInput,
            });
            setSas(result.sas);
            setStep("verify");
        } catch (err) {
            setError(err as string);
        }

        setLoading(false);
    };

    // Confirm SAS match and proceed to naming
    const handleConfirmSas = () => {
        setStep("name");
    };

    // Reject SAS - possible MITM
    const handleRejectSas = () => {
        setError("SAS mismatch! Possible man-in-the-middle attack. Exchange aborted.");
        setStep("scan");
        setQrInput("");
        setSas("");
    };

    // Finalize contact creation
    const handleCreateContact = async () => {
        if (!alias.trim()) {
            setError("Please enter a name for this contact");
            return;
        }

        setLoading(true);
        setError("");

        try {
            const contact = await invoke<Contact>("confirm_sas", {
                exchangeId,
                qrJson: qrInput,
                alias: alias.trim(),
            });
            setNewContact(contact);
            setStep("done");
            onContactAdded?.(contact);
        } catch (err) {
            setError(err as string);
        }

        setLoading(false);
    };

    // Render scan step
    const renderScanStep = () => (
        <div className="scanner-step">
            <div className="camera-frame">
                <div className="camera-placeholder">
                    <div className="camera-icon">📷</div>
                    <p className="text-muted">Camera access required</p>
                </div>
                <div className="scan-corners">
                    <div className="corner corner-tl" />
                    <div className="corner corner-tr" />
                    <div className="corner corner-bl" />
                    <div className="corner corner-br" />
                </div>
            </div>

            <p className="text-center text-muted mb-md">
                Or paste the QR code data below:
            </p>

            <textarea
                className="qr-input"
                placeholder='Paste QR JSON here ({"v":1,"pk":"..."})'
                value={qrInput}
                onChange={(e) => setQrInput(e.target.value)}
                rows={4}
            />

            <button
                className="btn btn-primary btn-block"
                onClick={handleProcessQr}
                disabled={loading}
            >
                {loading ? "Processing..." : "Process QR Code"}
            </button>
        </div>
    );

    // Render SAS verification step
    const renderVerifyStep = () => (
        <div className="scanner-step">
            <div className="sas-display">
                <h3 className="text-center mb-sm">Verify Code</h3>
                <p className="text-muted text-center mb-lg">
                    Read this code aloud with your contact
                </p>

                <div className="sas-code">
                    <span className="sas-word">{sas}</span>
                </div>

                <p className="text-muted text-center mt-lg">
                    Does your contact's screen show the same code?
                </p>
            </div>

            <div className="sas-buttons">
                <button
                    className="btn btn-primary btn-block"
                    onClick={handleConfirmSas}
                >
                    ✓ Yes, Codes Match
                </button>
                <button
                    className="btn btn-outline btn-block btn-danger"
                    onClick={handleRejectSas}
                >
                    ✕ No, Different Codes
                </button>
            </div>

            <div className="sas-warning">
                <span>⚠️</span>
                <span>If codes don't match, someone may be intercepting.</span>
            </div>
        </div>
    );

    // Render name contact step
    const renderNameStep = () => (
        <div className="scanner-step">
            <div className="success-icon">✓</div>
            <h3 className="text-center mb-sm text-quantum">Verified!</h3>
            <p className="text-muted text-center mb-lg">
                The connection is secure. Name this contact:
            </p>

            <input
                type="text"
                className="contact-name-input"
                placeholder="Contact name..."
                value={alias}
                onChange={(e) => setAlias(e.target.value)}
                autoFocus
            />

            <button
                className="btn btn-primary btn-block"
                onClick={handleCreateContact}
                disabled={loading}
            >
                {loading ? "Creating..." : "Add Contact"}
            </button>
        </div>
    );

    // Render done step
    const renderDoneStep = () => (
        <div className="scanner-step">
            <div className="success-icon large">🔐</div>
            <h3 className="text-center text-quantum">Contact Added!</h3>
            <p className="text-muted text-center mb-lg">
                You can now send encrypted messages to{" "}
                <span className="text-primary">{newContact?.alias}</span>
            </p>

            <div className="contact-card">
                <div className="contact-avatar">
                    {newContact?.alias.charAt(0).toUpperCase()}
                </div>
                <div className="contact-info">
                    <p className="contact-name">{newContact?.alias}</p>
                    <p className="contact-status text-quantum">✓ Verified</p>
                </div>
            </div>

            <button className="btn btn-primary btn-block" onClick={onClose}>
                Done
            </button>
        </div>
    );

    return (
        <div className="qr-scanner">
            <div className="scanner-header">
                <h3 className="mono">Add Contact</h3>
                {onClose && step !== "done" && (
                    <button className="close-btn" onClick={onClose}>
                        ✕
                    </button>
                )}
            </div>

            {/* Progress indicator */}
            <div className="progress-steps">
                <div className={`step-dot ${step !== "scan" ? "complete" : "active"}`} />
                <div className={`step-dot ${["name", "done"].includes(step) ? "complete" : step === "verify" ? "active" : ""}`} />
                <div className={`step-dot ${step === "done" ? "complete" : step === "name" ? "active" : ""}`} />
            </div>

            {error && (
                <div className="scanner-error">
                    <p className="text-amber">{error}</p>
                </div>
            )}

            {step === "scan" && renderScanStep()}
            {step === "verify" && renderVerifyStep()}
            {step === "name" && renderNameStep()}
            {step === "done" && renderDoneStep()}
        </div>
    );
}

export default QRScanner;
