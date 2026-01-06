import { useState, useEffect } from "react";
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

interface ContactListProps {
    onSelectContact?: (contact: Contact) => void;
    onAddContact?: () => void;
    decoyMode?: boolean;
}

/**
 * ContactList Component
 * 
 * Displays all contacts stored in memory with their verification status.
 * Contacts are ephemeral and will be lost on app restart (by design).
 */
export function ContactList({ onSelectContact, onAddContact, decoyMode = false }: ContactListProps) {
    const [contacts, setContacts] = useState<Contact[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

    // Load contacts on mount or when decoy mode changes
    useEffect(() => {
        loadContacts();
    }, [decoyMode]);

    const loadContacts = async () => {
        setLoading(true);
        setError("");

        try {
            if (decoyMode) {
                // Fetch decoy contacts
                const result: any[] = await invoke("get_decoy_contacts");
                // Map to Contact format
                const mapped: Contact[] = result.map(c => ({
                    id: c.id,
                    alias: c.name,
                    public_key: "",
                    kem_pubkey: "",
                    session_id: "decoy",
                    added_at: Math.floor(Date.now() / 1000), // Current time or parse from c.last_message_time
                    verified: true
                }));
                setContacts(mapped);
            } else {
                // Fetch real contacts
                const result = await invoke<Contact[]>("list_contacts");
                setContacts(result);
            }
        } catch (err) {
            setError(err as string);
        }

        setLoading(false);
    };

    // Delete a contact
    const handleDeleteContact = async (id: string) => {
        try {
            await invoke<boolean>("delete_contact", { contactId: id });
            setContacts((prev) => prev.filter((c) => c.id !== id));
            setDeleteConfirm(null);
        } catch (err) {
            setError(err as string);
        }
    };

    // Format timestamp
    const formatDate = (timestamp: number) => {
        const date = new Date(timestamp * 1000);
        const now = new Date();
        const diff = now.getTime() - date.getTime();

        if (diff < 60000) return "Just now";
        if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
        if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
        return date.toLocaleDateString();
    };

    // Render empty state
    const renderEmpty = () => (
        <div className="contacts-empty">
            <div className="empty-icon">👥</div>
            <h4>No Contacts Yet</h4>
            <p className="text-muted">
                Add contacts via QR code exchange or remote invite
            </p>
            {onAddContact && (
                <button className="btn btn-primary" onClick={onAddContact}>
                    + Add Contact
                </button>
            )}
        </div>
    );

    // Render contact item
    const renderContact = (contact: Contact) => (
        <div key={contact.id} className="contact-item">
            <div
                className="contact-main"
                onClick={() => onSelectContact?.(contact)}
            >
                <div className="contact-avatar">
                    {contact.alias.charAt(0).toUpperCase()}
                </div>
                <div className="contact-details">
                    <p className="contact-name">{contact.alias}</p>
                    <p className="contact-meta">
                        {contact.verified ? (
                            <span className="verified">✓ Verified</span>
                        ) : (
                            <span className="pending">⏳ Pending</span>
                        )}
                        <span className="separator">•</span>
                        <span className="added-time">{formatDate(contact.added_at)}</span>
                    </p>
                </div>
            </div>

            <div className="contact-actions">
                {deleteConfirm === contact.id ? (
                    <div className="delete-confirm">
                        <button
                            className="btn-icon btn-danger"
                            onClick={() => handleDeleteContact(contact.id)}
                        >
                            ✓
                        </button>
                        <button
                            className="btn-icon"
                            onClick={() => setDeleteConfirm(null)}
                        >
                            ✕
                        </button>
                    </div>
                ) : (
                    <button
                        className="btn-icon btn-delete"
                        onClick={() => setDeleteConfirm(contact.id)}
                        title="Delete contact"
                    >
                        🗑️
                    </button>
                )}
            </div>
        </div>
    );

    return (
        <div className="contact-list">
            <div className="contacts-header">
                <h3 className="mono">Contacts</h3>
                <div className="contacts-actions">
                    <button
                        className="btn-icon"
                        onClick={loadContacts}
                        title="Refresh"
                    >
                        ↻
                    </button>
                    {onAddContact && (
                        <button
                            className="btn btn-outline btn-sm"
                            onClick={onAddContact}
                        >
                            + Add
                        </button>
                    )}
                </div>
            </div>

            <div className="contacts-notice">
                <span>💾</span>
                <span className="text-muted">
                    Contacts are stored in memory only
                </span>
            </div>

            {error && (
                <div className="contacts-error">
                    <p className="text-amber">{error}</p>
                </div>
            )}

            {loading && (
                <div className="contacts-loading">
                    <div className="spinner" />
                    <p>Loading contacts...</p>
                </div>
            )}

            {!loading && contacts.length === 0 && renderEmpty()}

            {!loading && contacts.length > 0 && (
                <div className="contacts-list">
                    <p className="contacts-count text-muted">
                        {contacts.length} contact{contacts.length !== 1 ? "s" : ""}
                    </p>
                    {contacts.map(renderContact)}
                </div>
            )}
        </div>
    );
}

export default ContactList;
