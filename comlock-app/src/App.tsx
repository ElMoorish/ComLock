import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { QRDisplay, QRScanner, InviteFlow, ContactList, PinEntry, SecuritySettings } from "./components";
import "./App.css";

// Screen types
type Screen = "airlock" | "key-ceremony" | "contacts" | "chat" | "settings" | "lock";
type Modal = "none" | "qr-display" | "qr-scanner" | "invite";

// Types
interface CreateIdentityResult {
  mnemonic: string[];
  public_id: string;
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

interface Message {
  id: string;
  text: string;
  sent: boolean;
  status: "sending" | "mixing" | "delivered" | "decrypted";
  timestamp: Date;
}

function App() {
  const [screen, setScreen] = useState<Screen>("airlock");
  const [modal, setModal] = useState<Modal>("none");
  const [identity, setIdentity] = useState<CreateIdentityResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState("");
  const [activeContact, setActiveContact] = useState<Contact | null>(null);
  const [exchangeId, setExchangeId] = useState("");
  const [decoyMode, setDecoyMode] = useState(false);

  // Check security status on launch
  useEffect(() => {
    checkSecurity();
  }, []);

  const checkSecurity = async () => {
    try {
      const status: any = await invoke("get_security_status");
      if (status.is_decoy_mode) {
        setDecoyMode(true);
        loadDecoyData();
        setScreen("contacts"); // Skip lock
      } else if (status.security_enabled) {
        setScreen("lock");
      }
    } catch (e) {
      console.error("Security check failed", e);
    }
  };

  const loadDecoyData = async () => {
    try {
      const contacts: any[] = await invoke("get_decoy_contacts");
      // Decoy contacts available
      console.log("Decoy mode active, contacts available:", contacts.length);
      // We would update a contacts state here, but currently contacts are fetched by ContactList component.
      // Ideally pass this prop to ContactList or update how ContactList fetches.
    } catch (e) {
      console.error("Failed to load decoy data", e);
    }
  };

  const handleUnlock = async (result?: any) => {
    if (result && result.success) {
      if (result.is_decoy) {
        setDecoyMode(true);
        loadDecoyData();
      }
      setScreen("contacts"); // or last active screen
    }
  };

  // Simulate message status progression (only in normal mode)
  useEffect(() => {
    if (decoyMode) return;

    const interval = setInterval(() => {
      setMessages(prev => prev.map(msg => {
        if (msg.status === "sending") return { ...msg, status: "mixing" as const };
        if (msg.status === "mixing") return { ...msg, status: "delivered" as const };
        if (msg.status === "delivered") return { ...msg, status: "decrypted" as const };
        return msg;
      }));
    }, 1500);
    return () => clearInterval(interval);
  }, []);

  // Create identity handler
  const handleCreateIdentity = async () => {
    setLoading(true);
    try {
      const result = await invoke<CreateIdentityResult>("create_identity");
      setIdentity(result);
      setScreen("key-ceremony");
    } catch (error) {
      console.error("Failed to create identity:", error);
    }
    setLoading(false);
  };

  // Continue to contacts after key ceremony
  const handleContinue = () => {
    setScreen("contacts");
  };

  // Select a contact to chat with
  const handleSelectContact = async (contact: Contact) => {
    setActiveContact(contact);
    setScreen("chat");
    setMessages([]);

    if (decoyMode) {
      try {
        const decoyMsgs: any[] = await invoke("get_decoy_messages", { contactId: contact.id });
        const mappedMsgs: Message[] = decoyMsgs.map(m => ({
          id: m.id,
          text: m.text,
          sent: m.sent,
          status: "decrypted",
          timestamp: new Date()
        }));
        setMessages(mappedMsgs);
      } catch (e) {
        console.error("Failed to load decoy messages", e);
      }
    }
  };

  // Handle contact added
  const handleContactAdded = () => {
    setModal("none");
  };

  // Open add contact modal with QR display and scanner
  const handleAddContact = () => {
    setModal("qr-display");
  };

  // Send message handler
  const handleSendMessage = async () => {
    if (!inputText.trim()) return;

    const newMessage: Message = {
      id: Date.now().toString(),
      text: inputText,
      sent: true,
      status: "sending",
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, newMessage]);
    setInputText("");
  };

  // Render Airlock (Welcome) Screen
  const renderAirlock = () => (
    <div className="screen screen-center fade-in">
      <div className="shield-icon" />
      <h1 className="mono mb-md">ComLock</h1>
      <p className="text-secondary mb-xl">Maximum Secure Communication</p>

      <div className="btn-group">
        <button
          className="btn btn-primary btn-block"
          onClick={handleCreateIdentity}
          disabled={loading}
        >
          {loading ? "Generating..." : "Create Identity"}
        </button>
        <button className="btn btn-outline btn-block">
          Recover
        </button>
      </div>
    </div>
  );

  // Render Lock Screen
  const renderLockScreen = () => (
    <div className="screen fade-in" style={{ padding: 0 }}>
      <PinEntry
        mode="unlock"
        onSuccess={handleUnlock}
      />
    </div>
  );

  // Render Key Ceremony Screen
  const renderKeyCeremony = () => (
    <div className="screen fade-in">
      <div className="progress-steps">
        <div className="step-dot complete" />
        <div className="step-dot active" />
        <div className="step-dot" />
      </div>

      <h2 className="text-center mb-md">Key Ceremony</h2>
      <p className="text-secondary text-center mb-lg">
        Write down these 24 words in order
      </p>

      {identity && (
        <>
          <div className="mnemonic-grid">
            {identity.mnemonic.map((word, index) => (
              <div key={index} className="mnemonic-word">
                <span className="index">{index + 1}.</span>
                <span>{word}</span>
              </div>
            ))}
          </div>

          <div className="mnemonic-warning">
            <span>⚠️</span>
            <span>Write these down. Never screenshot.</span>
          </div>

          <p className="text-muted text-center mt-lg" style={{ fontSize: "0.875rem" }}>
            Your ID: <span className="text-quantum mono">{identity.public_id}</span>
          </p>

          <div className="btn-group mt-xl" style={{ margin: "0 auto" }}>
            <button
              className="btn btn-primary btn-block"
              onClick={handleContinue}
            >
              I've Written It Down
            </button>
          </div>
        </>
      )}
    </div>
  );

  // Render Contacts Screen
  const renderContacts = () => (
    <div className="screen fade-in" style={{ paddingBottom: "80px" }}>
      <ContactList
        onSelectContact={handleSelectContact}
        onAddContact={handleAddContact}
        decoyMode={decoyMode}
      />

      {/* Add Contact Options */}
      <div className="add-contact-options" style={{ marginTop: "var(--space-lg)" }}>
        <h4 className="text-muted mb-md" style={{ fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.05em" }}>
          Add Contact
        </h4>
        <div style={{ display: "flex", gap: "var(--space-md)" }}>
          <button
            className="btn btn-outline"
            style={{ flex: 1, minWidth: "auto" }}
            onClick={() => setModal("qr-display")}
          >
            📱 QR Code
          </button>
          <button
            className="btn btn-outline"
            style={{ flex: 1, minWidth: "auto" }}
            onClick={() => setModal("invite")}
          >
            📨 Remote
          </button>
        </div>
      </div>
    </div>
  );

  // Render Chat Screen
  const renderChat = () => (
    <div className="screen fade-in" style={{ padding: 0, paddingBottom: "80px" }}>
      <div className="chat-header">
        <div style={{ display: "flex", alignItems: "center", gap: "var(--space-md)" }}>
          <button
            onClick={() => setScreen("contacts")}
            style={{ background: "none", border: "none", color: "var(--text-primary)", cursor: "pointer", fontSize: "1.25rem" }}
          >
            ←
          </button>
          <span className="contact-name">{activeContact?.alias || "Unknown"}</span>
          <div className={`status-dot ${activeContact?.verified ? "" : "mixing"}`} />
        </div>
        <button
          className="text-secondary"
          onClick={() => setScreen("settings")}
          style={{ background: "none", border: "none", cursor: "pointer", fontSize: "1.25rem" }}
        >
          ⚙️
        </button>
      </div>

      <div className="chat-messages">
        {messages.length === 0 && (
          <p className="text-muted text-center" style={{ margin: "auto" }}>
            Start a secure conversation with {activeContact?.alias}
          </p>
        )}

        {messages.map(msg => (
          <div key={msg.id} className={`message ${msg.sent ? "message-sent" : "message-received"}`}>
            <p>{msg.text}</p>
            <div className={`message-status ${msg.status}`}>
              {msg.status === "sending" && "✓ Sending..."}
              {msg.status === "mixing" && (
                <>
                  <span className="mixing-wave">⌇</span>
                  <span>Mixing</span>
                </>
              )}
              {msg.status === "delivered" && "✓✓ Delivered"}
              {msg.status === "decrypted" && "✓✓ Decrypted"}
            </div>
          </div>
        ))}
      </div>

      <div className="chat-input">
        <input
          type="text"
          placeholder="Type a message..."
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSendMessage()}
        />
        <button className="send-btn" onClick={handleSendMessage}>
          →
        </button>
      </div>
    </div>
  );

  // Render Settings Screen
  const renderSettings = () => (
    <div className="screen fade-in" style={{ paddingBottom: "80px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "var(--space-md)", marginBottom: "var(--space-xl)" }}>
        <button
          onClick={() => setScreen(activeContact ? "chat" : "contacts")}
          style={{ background: "none", border: "none", color: "var(--text-primary)", cursor: "pointer", fontSize: "1.25rem" }}
        >
          ←
        </button>
        <h2 className="mono">Settings</h2>
      </div>

      <div className="settings-section">
        <h3>Anonymity</h3>
        <div className="card">
          <p className="setting-label mb-sm">Anonymity Budget</p>
          <p className="setting-description mb-md">
            Higher privacy uses more data but provides stronger protection
          </p>
          <div className="slider-container">
            <div className="slider-labels">
              <span>Low (500MB/mo)</span>
              <span className="text-quantum">Max (5GB/mo)</span>
            </div>
            <input type="range" className="slider" min="0" max="2" defaultValue="1" />
          </div>
        </div>
      </div>

      <div className="settings-section">
        <SecuritySettings />
      </div>

      <div className="settings-section">
        <h3>Identity</h3>
        <div className="card">
          <p className="setting-label mb-sm">Your ID</p>
          <p className="mono text-quantum">{identity?.public_id || "Not set"}</p>
        </div>
      </div>
    </div>
  );

  // Render Bottom Navigation
  const renderBottomNav = () => {
    if (["airlock", "key-ceremony"].includes(screen)) return null;

    return (
      <nav className="bottom-nav">
        <button
          className={`nav-item ${screen === "contacts" ? "active" : ""}`}
          onClick={() => setScreen("contacts")}
        >
          <span className="nav-icon">👥</span>
          <span>Contacts</span>
        </button>
        <button
          className={`nav-item ${screen === "chat" ? "active" : ""}`}
          onClick={() => activeContact && setScreen("chat")}
          disabled={!activeContact}
        >
          <span className="nav-icon">💬</span>
          <span>Chat</span>
        </button>
        <button
          className={`nav-item ${screen === "settings" ? "active" : ""}`}
          onClick={() => setScreen("settings")}
        >
          <span className="nav-icon">⚙️</span>
          <span>Settings</span>
        </button>
      </nav>
    );
  };

  // Render Modal
  const renderModal = () => {
    if (modal === "none") return null;

    return (
      <div className="modal-overlay" onClick={() => setModal("none")}>
        <div className="modal-content" onClick={(e) => e.stopPropagation()}>
          {modal === "qr-display" && (
            <div>
              <QRDisplay
                onScanReady={(id) => setExchangeId(id)}
                onClose={() => setModal("none")}
              />
              <div style={{ marginTop: "var(--space-lg)", textAlign: "center" }}>
                <button
                  className="btn btn-outline btn-block"
                  onClick={() => setModal("qr-scanner")}
                >
                  📷 Scan Their Code
                </button>
              </div>
            </div>
          )}
          {modal === "qr-scanner" && (
            <QRScanner
              exchangeId={exchangeId}
              onContactAdded={handleContactAdded}
              onClose={() => setModal("none")}
            />
          )}
          {modal === "invite" && (
            <InviteFlow
              onContactAdded={handleContactAdded}
              onClose={() => setModal("none")}
            />
          )}
        </div>
      </div>
    );
  };

  // Main render
  return (
    <div className="app-container">
      {screen === "lock" && renderLockScreen()}
      {screen === "airlock" && renderAirlock()}
      {screen === "key-ceremony" && renderKeyCeremony()}
      {screen === "contacts" && renderContacts()}
      {screen === "chat" && renderChat()}
      {screen === "settings" && renderSettings()}
      {renderBottomNav()}
      {renderModal()}
    </div>
  );
}

export default App;

