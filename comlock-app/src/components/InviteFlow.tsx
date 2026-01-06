import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface Contact {
    id: string;
    alias: string;
    public_key: string;
    kem_pubkey: string;
    session_id: string;
    added_at: number;
    verified: boolean;
}

interface InviteFlowProps {
    onContactAdded?: (contact: Contact) => void;
    onClose?: () => void;
}

/**
 * InviteFlow Component
 * 
 * Handles remote contact exchange via one-time invite blobs.
 * Supports both generating invites and importing received invites.
 */
export function InviteFlow({ onContactAdded, onClose }: InviteFlowProps) {
    const [mode, setMode] = useState<"menu" | "generate" | "import">("menu");
    const [inviteBlob, setInviteBlob] = useState("");
    const [importBlob, setImportBlob] = useState("");
    const [alias, setAlias] = useState("");
    const [ttlHours, setTtlHours] = useState(24);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [copied, setCopied] = useState(false);
    const [newContact, setNewContact] = useState<Contact | null>(null);

    // Generate a new invite blob
    const handleGenerateInvite = async () => {
        setLoading(true);
        setError("");

        try {
            const blob = await invoke<string>("generate_invite", {
                ttlHours: ttlHours,
            });
            setInviteBlob(blob);
        } catch (err) {
            setError(err as string);
        }

        setLoading(false);
    };

    // Copy invite to clipboard
    const handleCopyInvite = async () => {
        try {
            await navigator.clipboard.writeText(inviteBlob);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch (err) {
            setError("Failed to copy to clipboard");
        }
    };

    // Import a received invite blob
    const handleImportInvite = async () => {
        if (!importBlob.trim()) {
            setError("Please paste an invite blob");
            return;
        }
        if (!alias.trim()) {
            setError("Please enter a name for this contact");
            return;
        }

        setLoading(true);
        setError("");

        try {
            const contact = await invoke<Contact>("import_invite", {
                inviteB64: importBlob.trim(),
                alias: alias.trim(),
            });
            setNewContact(contact);
            onContactAdded?.(contact);
        } catch (err) {
            setError(err as string);
        }

        setLoading(false);
    };

    // Render mode selection menu
    const renderMenu = () => (
        <div className="invite-menu">
            <p className="text-muted text-center mb-lg">
                Exchange contacts securely without meeting in person
            </p>

            <button
                className="invite-option"
                onClick={() => setMode("generate")}
            >
                <div className="option-icon">📤</div>
                <div className="option-content">
                    <h4>Send Invite</h4>
                    <p className="text-muted">Generate a one-time invite to share</p>
                </div>
                <span className="option-arrow">→</span>
            </button>

            <button
                className="invite-option"
                onClick={() => setMode("import")}
            >
                <div className="option-icon">📥</div>
                <div className="option-content">
                    <h4>Receive Invite</h4>
                    <p className="text-muted">Import an invite you received</p>
                </div>
                <span className="option-arrow">→</span>
            </button>

            <div className="invite-warning">
                <span>⚠️</span>
                <span className="text-muted">
                    Share invites through a trusted channel (Signal, encrypted email, etc.)
                </span>
            </div>
        </div>
    );

    // Render generate invite screen
    const renderGenerate = () => (
        <div className="invite-generate">
            <button className="back-btn" onClick={() => setMode("menu")}>
                ← Back
            </button>

            <h4 className="text-center mb-md">Generate Invite</h4>

            <div className="ttl-selector">
                <label className="text-muted">Expires after:</label>
                <div className="ttl-options">
                    {[1, 24, 168].map((hours) => (
                        <button
                            key={hours}
                            className={`ttl-option ${ttlHours === hours ? "active" : ""}`}
                            onClick={() => setTtlHours(hours)}
                        >
                            {hours === 1 ? "1 hour" : hours === 24 ? "24 hours" : "7 days"}
                        </button>
                    ))}
                </div>
            </div>

            {!inviteBlob && (
                <button
                    className="btn btn-primary btn-block"
                    onClick={handleGenerateInvite}
                    disabled={loading}
                >
                    {loading ? "Generating..." : "Generate Invite"}
                </button>
            )}

            {inviteBlob && (
                <div className="invite-blob-container">
                    <p className="text-muted mb-sm">Your invite code:</p>
                    <div className="invite-blob">
                        <code>{inviteBlob.slice(0, 50)}...</code>
                    </div>

                    <button
                        className={`btn btn-block ${copied ? "btn-primary" : "btn-outline"}`}
                        onClick={handleCopyInvite}
                    >
                        {copied ? "✓ Copied!" : "📋 Copy Invite"}
                    </button>

                    <p className="text-muted text-center mt-md">
                        Send this to your contact via a secure channel.
                        <br />
                        They will send you an acknowledgment back.
                    </p>
                </div>
            )}
        </div>
    );

    // Render import invite screen
    const renderImport = () => (
        <div className="invite-import">
            <button className="back-btn" onClick={() => setMode("menu")}>
                ← Back
            </button>

            {!newContact ? (
                <>
                    <h4 className="text-center mb-md">Import Invite</h4>
                    <p className="text-muted text-center mb-lg">
                        Paste the invite code you received
                    </p>

                    <textarea
                        className="invite-input"
                        placeholder="Paste invite blob here..."
                        value={importBlob}
                        onChange={(e) => setImportBlob(e.target.value)}
                        rows={4}
                    />

                    <input
                        type="text"
                        className="contact-name-input"
                        placeholder="Contact name..."
                        value={alias}
                        onChange={(e) => setAlias(e.target.value)}
                    />

                    <button
                        className="btn btn-primary btn-block"
                        onClick={handleImportInvite}
                        disabled={loading}
                    >
                        {loading ? "Importing..." : "Import Contact"}
                    </button>

                    <div className="invite-info">
                        <span>ℹ️</span>
                        <span className="text-muted">
                            After importing, an encrypted ACK will be sent back via the mixnet
                        </span>
                    </div>
                </>
            ) : (
                <div className="import-success">
                    <div className="success-icon large">✓</div>
                    <h4 className="text-center text-quantum">Contact Imported!</h4>
                    <p className="text-muted text-center mb-lg">
                        Pending verification via mixnet
                    </p>

                    <div className="contact-card">
                        <div className="contact-avatar">
                            {newContact.alias.charAt(0).toUpperCase()}
                        </div>
                        <div className="contact-info">
                            <p className="contact-name">{newContact.alias}</p>
                            <p className="contact-status text-amber">⏳ Pending ACK</p>
                        </div>
                    </div>

                    <button className="btn btn-primary btn-block" onClick={onClose}>
                        Done
                    </button>
                </div>
            )}
        </div>
    );

    return (
        <div className="invite-flow">
            <div className="invite-header">
                <h3 className="mono">Remote Invite</h3>
                {onClose && (
                    <button className="close-btn" onClick={onClose}>
                        ✕
                    </button>
                )}
            </div>

            {error && (
                <div className="invite-error">
                    <p className="text-amber">{error}</p>
                </div>
            )}

            {mode === "menu" && renderMenu()}
            {mode === "generate" && renderGenerate()}
            {mode === "import" && renderImport()}
        </div>
    );
}

export default InviteFlow;
