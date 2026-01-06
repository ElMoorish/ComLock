import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { PinEntry } from "./PinEntry";
import "./SecuritySettings.css";

interface SecurityStatus {
    security_enabled: boolean;
    has_pin: boolean;
    has_duress_pin: boolean;
    dead_man_days: number;
    days_until_wipe: number | null;
    panic_gesture_enabled: boolean;
    failed_attempts: number;
}

export function SecuritySettings() {
    const [status, setStatus] = useState<SecurityStatus | null>(null);
    const [activeModal, setActiveModal] = useState<"none" | "setup-pin" | "setup-duress">("none");

    useEffect(() => {
        loadStatus();
    }, []);

    const loadStatus = async () => {
        try {
            const s = await invoke<SecurityStatus>("get_security_status");
            setStatus(s);
        } catch (e) {
            console.error(e);
        }
    };

    const handleSetupPin = async (pin: string) => {
        try {
            await invoke("setup_pin", { pin });
            setActiveModal("none");
            loadStatus();
        } catch (e) {
            alert(e);
        }
    };

    const handleSetupDuressPin = async (pin: string) => {
        try {
            await invoke("setup_duress_pin", { duressPin: pin });
            setActiveModal("none");
            loadStatus();
        } catch (e) {
            alert(e);
        }
    };

    const togglePanicGesture = async (enabled: boolean) => {
        try {
            await invoke("toggle_panic_gesture", { enabled });
            loadStatus();
        } catch (e) {
            console.error(e);
        }
    };

    const handleDeadManChange = async (e: React.ChangeEvent<HTMLSelectElement>) => {
        const days = parseInt(e.target.value);
        try {
            await invoke("configure_dead_man", { days });
            loadStatus();
        } catch (err) {
            console.error(err);
        }
    };

    if (!status) return <div>Loading security settings...</div>;

    return (
        <div className="security-settings">
            <h2>SECURITY & PANIC LAYER</h2>

            <div className="setting-card">
                <div className="setting-header">
                    <h3>App Lock</h3>
                    <span className={status.security_enabled ? "status-on" : "status-off"}>
                        {status.security_enabled ? "ENABLED" : "DISABLED"}
                    </span>
                </div>
                <p>Require PIN to access ComLock.</p>
                <button
                    className="action-btn"
                    onClick={() => setActiveModal("setup-pin")}
                >
                    {status.has_pin ? "CHANGE PIN" : "SET PIN"}
                </button>
            </div>

            <div className="setting-card danger-zone">
                <div className="setting-header">
                    <h3>Duress PIN</h3>
                    <span className={status.has_duress_pin ? "status-on" : "status-off"}>
                        {status.has_duress_pin ? "ENABLED" : "NOT SET"}
                    </span>
                </div>
                <p>
                    Entering this PIN will silently wipe keys and show a decoy vault.
                    <strong> MUST be different from your normal PIN.</strong>
                </p>
                <button
                    className="action-btn"
                    onClick={() => setActiveModal("setup-duress")}
                    disabled={!status.has_pin}
                >
                    {status.has_duress_pin ? "CHANGE DURESS PIN" : "SET DURESS PIN"}
                </button>
            </div>

            <div className="setting-card">
                <div className="setting-header">
                    <h3>Dead Man's Switch</h3>
                    <span className={status.dead_man_days > 0 ? "status-on" : "status-off"}>
                        {status.dead_man_days > 0 ? `${status.dead_man_days} DAYS` : "DISABLED"}
                    </span>
                </div>
                <p>Automatically wipe data if app is not opened for a set duration.</p>
                <select
                    value={status.dead_man_days}
                    onChange={handleDeadManChange}
                    className="security-select"
                >
                    <option value="0">Disabled</option>
                    <option value="1">1 Day</option>
                    <option value="3">3 Days</option>
                    <option value="7">7 Days</option>
                    <option value="14">14 Days</option>
                    <option value="30">30 Days</option>
                </select>
                {status.days_until_wipe !== null && (
                    <div className="warning-text">
                        ⚠️ Wipe scheduled in {status.days_until_wipe} days if inactive.
                    </div>
                )}
            </div>

            <div className="setting-card">
                <div className="setting-header">
                    <h3>Panic Gesture</h3>
                    <label className="switch">
                        <input
                            type="checkbox"
                            checked={status.panic_gesture_enabled}
                            onChange={(e) => togglePanicGesture(e.target.checked)}
                        />
                        <span className="slider round"></span>
                    </label>
                </div>
                <p>Long press with 3 fingers anywhere to trigger immediate wipe.</p>
            </div>

            {activeModal === "setup-pin" && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <PinWizard
                            title="SET APP PIN"
                            onComplete={handleSetupPin}
                            onCancel={() => setActiveModal("none")}
                        />
                    </div>
                </div>
            )}

            {activeModal === "setup-duress" && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <PinWizard
                            title="SET DURESS PIN"
                            onComplete={handleSetupDuressPin}
                            onCancel={() => setActiveModal("none")}
                        />
                    </div>
                </div>
            )}
        </div>
    );
}

function PinWizard({ title, onComplete, onCancel }: {
    title: string,
    onComplete: (pin: string) => void,
    onCancel: () => void
}) {
    const [step, setStep] = useState<"enter" | "confirm">("enter");
    const [firstPin, setFirstPin] = useState("");

    const handleStep1 = (result: any) => {
        setFirstPin(result.reason);
        setStep("confirm");
    };

    const handleStep2 = () => {
        onComplete(firstPin);
    };

    return (
        <div className="pin-wizard-container" style={{ textAlign: "center" }}>
            <h3 className="mono mb-md" style={{ color: "var(--primary-color)" }}>
                {step === "enter" ? title : "Repeat PIN to Confirm"}
            </h3>
            <PinEntry
                mode={step === "enter" ? "setup" : "confirm"}
                setupPin={firstPin}
                onSuccess={step === "enter" ? handleStep1 : handleStep2}
                onCancel={onCancel}
            />
        </div>
    );
}
