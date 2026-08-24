"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import useWebSocket, { ReadyState } from "react-use-websocket";
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  AlertTriangle,
  Brain,
  CheckCircle2,
  Clock,
  Globe,
  Radio,
  Server,
  Zap,
  ChevronRight,
  Send,
  Terminal,
  Lock,
} from "lucide-react";
import BlastRadiusGraph, { GraphNode, GraphLink } from "@/components/BlastRadiusGraph";

// ─── Interfaces ─────────────────────────────────────────────────────────────

interface RiskInfo {
  risk_score: number;
  autonomous_action: boolean;
  status: string;
  action: string;
}

interface IncidentRecord {
  id: string;
  timestamp: string;
  event_id: number;
  incident_id: number;
  source_ip: string;
  threat_level: "critical" | "high" | "medium" | "low" | "info" | string;
  confidence_score: number;
  mitre_tactic: string;
  mitre_technique: string;
  cve_references: string[];
  reasoning: string;
  recommended_action: string;
  risk: RiskInfo;
  graph?: {
    nodes: GraphNode[];
    links: GraphLink[];
  };
}

// ─── Helper utilities ───────────────────────────────────────────────────────

const THREAT_COLORS: Record<
  string,
  { text: string; bg: string; border: string; glow: string }
> = {
  critical: {
    text: "text-red-400",
    bg: "bg-red-950/40",
    border: "border-red-500/40",
    glow: "shadow-[0_0_15px_rgba(239,68,68,0.3)]",
  },
  high: {
    text: "text-orange-400",
    bg: "bg-orange-950/40",
    border: "border-orange-500/40",
    glow: "shadow-[0_0_15px_rgba(249,115,22,0.3)]",
  },
  medium: {
    text: "text-amber-400",
    bg: "bg-amber-950/40",
    border: "border-amber-500/40",
    glow: "shadow-[0_0_15px_rgba(245,158,11,0.2)]",
  },
  low: {
    text: "text-emerald-400",
    bg: "bg-emerald-950/40",
    border: "border-emerald-500/40",
    glow: "shadow-[0_0_15px_rgba(16,185,129,0.2)]",
  },
  info: {
    text: "text-cyan-400",
    bg: "bg-cyan-950/40",
    border: "border-cyan-500/40",
    glow: "",
  },
};

function getThreatStyle(level: string) {
  return THREAT_COLORS[level.toLowerCase()] || THREAT_COLORS.info;
}

function formatTime(ts?: string) {
  if (!ts) return "";
  try {
    return new Date(ts).toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return ts;
  }
}

// ─── Main Component ─────────────────────────────────────────────────────────

export default function DashboardPage() {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<IncidentRecord | null>(null);
  const [isApproving, setIsApproving] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const feedScrollRef = useRef<HTMLDivElement>(null);

  // WebSocket connection using react-use-websocket
  const socketUrl = "ws://localhost:8000/ws/console";
  const { lastJsonMessage, readyState } = useWebSocket(socketUrl, {
    shouldReconnect: () => true,
    reconnectInterval: 3000,
    reconnectAttempts: 100,
  });

  // Handle incoming live WebSocket messages
  useEffect(() => {
    if (!lastJsonMessage) return;
    const msg = lastJsonMessage as any;

    if (msg.type === "new_event") {
      const record: IncidentRecord = {
        id: `${msg.event_id}-${Date.now()}`,
        timestamp: msg.timestamp || new Date().toISOString(),
        event_id: msg.event_id,
        incident_id: msg.incident_id,
        source_ip: msg.source_ip,
        threat_level: msg.threat_level || "medium",
        confidence_score: msg.confidence_score ?? 0.8,
        mitre_tactic: msg.mitre_tactic || "Initial Access",
        mitre_technique: msg.mitre_technique || "Exploit Public-Facing App",
        cve_references: msg.cve_references || [],
        reasoning: msg.reasoning || "Security telemetry parsed.",
        recommended_action: msg.recommended_action || "Block source IP.",
        risk: msg.risk || {
          risk_score: 0.5,
          autonomous_action: false,
          status: "staged_for_human",
          action: "require_analyst_approval",
        },
        graph: msg.graph || { nodes: [], links: [] },
      };

      setIncidents((prev) => [record, ...prev.filter((i) => i.incident_id !== record.incident_id)].slice(0, 40));
      setSelectedIncident(record);
    } else if (msg.type === "incident_approved") {
      setIncidents((prev) =>
        prev.map((inc) =>
          inc.incident_id === msg.incident_id
            ? {
                ...inc,
                risk: {
                  ...inc.risk,
                  autonomous_action: true,
                  status: "resolved",
                  action: "human_approved_resolved",
                },
              }
            : inc
        )
      );

      setSelectedIncident((prev) =>
        prev?.incident_id === msg.incident_id
          ? {
              ...prev,
              risk: {
                ...prev.risk,
                autonomous_action: true,
                status: "resolved",
                action: "human_approved_resolved",
              },
            }
          : prev
      );
    }
  }, [lastJsonMessage]);

  // Handle analyst approval POST request
  const handleApproveAction = useCallback(async (incidentId: number) => {
    setIsApproving(true);
    try {
      const res = await fetch(`http://localhost:8000/api/incidents/${incidentId}/approve`, {
        method: "POST",
      });
      if (!res.ok) throw new Error("Approval request failed");
      const data = await res.json();

      setIncidents((prev) =>
        prev.map((inc) =>
          inc.incident_id === incidentId
            ? {
                ...inc,
                risk: {
                  ...inc.risk,
                  autonomous_action: true,
                  status: "resolved",
                  action: "human_approved_resolved",
                },
              }
            : inc
        )
      );

      setSelectedIncident((prev) =>
        prev?.incident_id === incidentId
          ? {
              ...prev,
              risk: {
                ...prev.risk,
                autonomous_action: true,
                status: "resolved",
                action: "human_approved_resolved",
              },
            }
          : prev
      );
    } catch (err) {
      console.error("Failed to approve incident:", err);
    } finally {
      setIsApproving(false);
    }
  }, []);

  // Quick simulate security event trigger
  const handleSimulateAttack = async () => {
    setIsSimulating(true);
    try {
      const sampleIps = ["45.33.32.156", "185.220.101.5", "194.26.29.112", "91.240.118.172"];
      const samplePayloads = [
        { path: "/admin/config.php", method: "POST" },
        { path: "/etc/passwd", method: "GET" },
        { query: "UNION SELECT null, username, password FROM admin", method: "POST" },
        { path: "/api/v1/debug/shell?cmd=whoami", method: "GET" },
      ];
      const randomIp = sampleIps[Math.floor(Math.random() * sampleIps.length)];
      const randomPayload = samplePayloads[Math.floor(Math.random() * samplePayloads.length)];

      await fetch("http://localhost:8000/api/ingest", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_ip: randomIp,
          payload: randomPayload,
          blast_radius_hosts: 2,
          asset_criticality: 0.9,
          decoy_used: true,
        }),
      });
    } catch (err) {
      console.error("Simulation failed:", err);
    } finally {
      setIsSimulating(false);
    }
  };

  const isWsConnected = readyState === ReadyState.OPEN;
  const isWsConnecting = readyState === ReadyState.CONNECTING;

  // Active graph data fallback
  const activeGraph = selectedIncident?.graph || {
    nodes: [
      { id: "1", name: selectedIncident?.source_ip || "185.220.101.5", type: "attacker_ip" },
      { id: "2", name: "web-prod-01", type: "target_host" },
      { id: "3", name: "decoy-login-trap", type: "decoy_honeypot" },
    ],
    links: [
      { source: "1", target: "2", type: "targeted" },
      { source: "2", target: "3", type: "redirected_to" },
    ],
  };

  const riskScore = selectedIncident?.risk?.risk_score ?? 0;
  const isStagedForApproval = selectedIncident?.risk?.status === "staged_for_human" || (!selectedIncident?.risk?.autonomous_action && selectedIncident?.risk?.status !== "resolved");
  const isResolved = selectedIncident?.risk?.status === "resolved";

  return (
    <div className="min-h-screen flex flex-col bg-[#040404] text-white">
      {/* ── Top Navigation / Telemetry Bar ── */}
      <header className="px-6 py-3 border-b border-white/10 flex items-center justify-between bg-black/40 backdrop-blur-md sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500 via-purple-500 to-pink-500 flex items-center justify-center p-0.5 shadow-[0_0_15px_rgba(99,102,241,0.5)]">
            <div className="w-full h-full bg-[#080808] rounded-[6px] flex items-center justify-center">
              <ShieldAlert className="w-4 h-4 text-indigo-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-sm tracking-wider uppercase bg-gradient-to-r from-white via-neutral-200 to-neutral-400 bg-clip-text text-transparent">
                Chimera SOC
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-950/60 border border-indigo-500/30 text-indigo-300">
                v0.2 Autonomous
              </span>
            </div>
            <p className="text-[10px] text-neutral-500 font-mono">
              Risk-Weighted Autonomy & Threat Intelligence Layer
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* WebSocket Status */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/[0.03] border border-white/10 text-xs">
            <div
              className={`w-2 h-2 rounded-full ${
                isWsConnected
                  ? "bg-emerald-400 shadow-[0_0_8px_#34d399]"
                  : isWsConnecting
                  ? "bg-amber-400 animate-pulse"
                  : "bg-rose-500"
              }`}
            />
            <span className="text-neutral-300 text-xs font-mono">
              {isWsConnected ? "LIVE STREAM" : isWsConnecting ? "CONNECTING..." : "DISCONNECTED"}
            </span>
          </div>

          {/* Incident Count */}
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-white/[0.03] border border-white/10 text-xs text-neutral-400 font-mono">
            <Activity className="w-3.5 h-3.5 text-indigo-400" />
            <span>{incidents.length} Events Logged</span>
          </div>

          {/* Quick Simulation Trigger */}
          <button
            onClick={handleSimulateAttack}
            disabled={isSimulating}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600/30 hover:bg-indigo-600/50 border border-indigo-500/40 text-indigo-200 text-xs font-medium transition-all shadow-[0_0_10px_rgba(99,102,241,0.2)] active:scale-95 disabled:opacity-50"
          >
            <Send className="w-3 h-3" />
            <span>{isSimulating ? "Injecting..." : "Simulate Telemetry"}</span>
          </button>
        </div>
      </header>

      {/* ── Main 3-Column Dashboard Layout ── */}
      <main className="flex-1 p-4 grid grid-cols-12 gap-4 max-h-[calc(100vh-61px)] min-h-[calc(100vh-61px)] overflow-hidden">
        {/* ── Column 1: Live Incident Feed (Left) ── */}
        <section className="col-span-3 flex flex-col glass-panel p-4 overflow-hidden border border-white/10">
          <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-3">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-indigo-400" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-neutral-200">
                Live Incident Feed
              </h2>
            </div>
            <span className="text-[10px] font-mono text-neutral-500">
              {incidents.length} Intercepted
            </span>
          </div>

          <div
            ref={feedScrollRef}
            className="flex-1 overflow-y-auto space-y-2 pr-1"
          >
            {incidents.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-4 text-neutral-600">
                <Radio className="w-8 h-8 mb-2 stroke-[1.5] animate-pulse text-neutral-500" />
                <p className="text-xs font-medium text-neutral-400">Listening for telemetry</p>
                <p className="text-[10px] text-neutral-600 mt-1">
                  POST to <code className="text-indigo-400">/api/ingest</code> or click Simulate
                </p>
              </div>
            ) : (
              incidents.map((inc) => {
                const isSelected = selectedIncident?.incident_id === inc.incident_id;
                const threatStyle = getThreatStyle(inc.threat_level);
                return (
                  <div
                    key={inc.id}
                    onClick={() => setSelectedIncident(inc)}
                    className={`p-3 rounded-lg border transition-all cursor-pointer text-left relative overflow-hidden ${
                      isSelected
                        ? "bg-white/[0.08] border-indigo-500/60 shadow-[0_0_15px_rgba(99,102,241,0.15)] ring-1 ring-indigo-500/40"
                        : "bg-white/[0.02] border-white/5 hover:border-white/20 hover:bg-white/[0.04]"
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span
                        className={`text-[9px] font-mono font-bold uppercase px-2 py-0.5 rounded-full border ${threatStyle.bg} ${threatStyle.text} ${threatStyle.border}`}
                      >
                        {inc.threat_level}
                      </span>
                      <span className="text-[10px] font-mono text-neutral-500 flex items-center gap-1">
                        <Clock className="w-2.5 h-2.5" />
                        {formatTime(inc.timestamp)}
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 font-mono text-xs font-semibold text-neutral-200 mb-1 truncate">
                      <Globe className="w-3 h-3 text-neutral-500 shrink-0" />
                      <span>{inc.source_ip}</span>
                    </div>

                    <p className="text-[11px] text-neutral-400 truncate mb-1">
                      {inc.mitre_tactic} · {inc.mitre_technique}
                    </p>

                    <div className="flex items-center justify-between text-[10px] font-mono pt-1.5 border-t border-white/5 text-neutral-500">
                      <span>INC-{inc.incident_id}</span>
                      <span
                        className={
                          inc.risk?.status === "resolved"
                            ? "text-emerald-400"
                            : inc.risk?.autonomous_action
                            ? "text-cyan-400"
                            : "text-amber-400"
                        }
                      >
                        {inc.risk?.status === "resolved"
                          ? "✓ Resolved"
                          : inc.risk?.autonomous_action
                          ? "⚡ Auto-Mitigated"
                          : "⚠️ Staged (Human)"}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </section>

        {/* ── Column 2: Blast-Radius Graph (Center) ── */}
        <section className="col-span-6 flex flex-col glass-panel p-4 overflow-hidden border border-white/10">
          <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-2">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-violet-400" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-neutral-200">
                Attack Path & Blast-Radius Graph
              </h2>
            </div>
            {selectedIncident && (
              <div className="flex items-center gap-2 text-[10px] font-mono text-neutral-400">
                <span className="px-2 py-0.5 rounded bg-white/5 border border-white/10">
                  Target: web-prod-01
                </span>
                <span className="px-2 py-0.5 rounded bg-amber-950/40 text-amber-300 border border-amber-500/30">
                  Honeypot Active
                </span>
              </div>
            )}
          </div>

          {/* Graph Visualization Container */}
          <div className="flex-1 relative rounded-lg bg-black/40 border border-white/5 overflow-hidden flex items-center justify-center">
            {selectedIncident ? (
              <BlastRadiusGraph
                nodes={activeGraph.nodes}
                links={activeGraph.links}
              />
            ) : (
              <div className="flex flex-col items-center justify-center text-center p-6 text-neutral-600">
                <Globe className="w-12 h-12 mb-3 stroke-[1] text-neutral-700 animate-pulse" />
                <p className="text-sm font-medium text-neutral-400">No Incident Selected</p>
                <p className="text-xs text-neutral-600 mt-1 max-w-sm">
                  Select an incident from the feed or simulate an attack to visualize the active MITRE attack vectors and blast radius.
                </p>
              </div>
            )}

            {/* Graph Legend Overlay */}
            <div className="absolute bottom-3 left-3 bg-black/70 backdrop-blur-md border border-white/10 rounded-lg p-2 flex items-center gap-3 text-[10px] font-mono">
              <div className="flex items-center gap-1">
                <div className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-[0_0_6px_#ef4444]" />
                <span className="text-neutral-400">Attacker IP</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2.5 h-2.5 rounded-full bg-blue-500 shadow-[0_0_6px_#3b82f6]" />
                <span className="text-neutral-400">Target Host</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-2.5 h-2.5 rounded-full bg-amber-500 shadow-[0_0_6px_#f59e0b]" />
                <span className="text-neutral-400">Decoy Trap</span>
              </div>
            </div>
          </div>
        </section>

        {/* ── Column 3: AI Agent Reasoning & Risk Dial (Right) ── */}
        <section className="col-span-3 flex flex-col glass-panel p-4 overflow-hidden border border-white/10">
          <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-3">
            <div className="flex items-center gap-2">
              <Brain className="w-4 h-4 text-pink-400" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-neutral-200">
                AI Agent Triage & Risk Dial
              </h2>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto space-y-4 pr-1">
            {selectedIncident ? (
              <>
                {/* ── Risk Dial Gauge ── */}
                <div className="p-4 rounded-xl bg-white/[0.03] border border-white/10 flex flex-col items-center text-center relative overflow-hidden">
                  <div className="relative w-28 h-28 flex items-center justify-center my-1">
                    <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                      <circle
                        cx="50"
                        cy="50"
                        r="40"
                        className="stroke-neutral-800"
                        strokeWidth="8"
                        fill="transparent"
                      />
                      <circle
                        cx="50"
                        cy="50"
                        r="40"
                        stroke={
                          riskScore >= 0.7
                            ? "#ef4444"
                            : riskScore >= 0.4
                            ? "#f97316"
                            : "#10b981"
                        }
                        strokeWidth="8"
                        strokeDasharray={2 * Math.PI * 40}
                        strokeDashoffset={
                          2 * Math.PI * 40 * (1 - Math.min(1, Math.max(0, riskScore)))
                        }
                        strokeLinecap="round"
                        fill="transparent"
                        className="transition-all duration-700 ease-out"
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-2xl font-bold font-mono tracking-tight text-white">
                        {Math.round(riskScore * 100)}%
                      </span>
                      <span className="text-[9px] font-mono uppercase text-neutral-500">
                        Risk Score
                      </span>
                    </div>
                  </div>

                  {/* Autonomy Decision Pill */}
                  <div className="mt-2">
                    {isResolved ? (
                      <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-[11px] font-bold bg-emerald-950/60 text-emerald-300 border border-emerald-500/40">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Human Approved & Resolved
                      </span>
                    ) : isStagedForApproval ? (
                      <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-[11px] font-bold bg-orange-950/60 text-orange-300 border border-orange-500/40 animate-pulse">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        Staged for Analyst Approval
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-[11px] font-bold bg-cyan-950/60 text-cyan-300 border border-cyan-500/40">
                        <Zap className="w-3.5 h-3.5" />
                        Autonomous Action Executed
                      </span>
                    )}
                  </div>
                </div>

                {/* ── Confidence & MITRE Breakdown ── */}
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between items-center text-neutral-400">
                    <span className="text-[10px] uppercase tracking-wider font-mono">
                      Model Confidence:
                    </span>
                    <span className="font-mono text-neutral-200 font-bold">
                      {Math.round(selectedIncident.confidence_score * 100)}%
                    </span>
                  </div>
                  <div className="w-full bg-neutral-800 h-1.5 rounded-full overflow-hidden">
                    <div
                      className="bg-indigo-500 h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${Math.round(selectedIncident.confidence_score * 100)}%`,
                      }}
                    />
                  </div>

                  <div className="p-3 rounded-lg bg-white/[0.02] border border-white/5 space-y-1.5 mt-3">
                    <div className="flex justify-between">
                      <span className="text-neutral-500 text-[10px] uppercase font-mono">Tactic:</span>
                      <span className="font-semibold text-neutral-200 text-right">
                        {selectedIncident.mitre_tactic}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-neutral-500 text-[10px] uppercase font-mono">Technique:</span>
                      <span className="text-indigo-300 text-right font-mono text-[11px]">
                        {selectedIncident.mitre_technique}
                      </span>
                    </div>
                    {selectedIncident.cve_references?.length > 0 && (
                      <div className="flex justify-between items-start pt-1">
                        <span className="text-neutral-500 text-[10px] uppercase font-mono">CVE:</span>
                        <div className="flex flex-wrap gap-1 justify-end">
                          {selectedIncident.cve_references.map((cve) => (
                            <span
                              key={cve}
                              className="px-1.5 py-0.5 rounded bg-red-950/40 border border-red-500/30 text-red-300 font-mono text-[9px]"
                            >
                              {cve}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* ── AI Reasoning Log ── */}
                <div className="space-y-1.5">
                  <span className="text-[10px] uppercase tracking-wider font-mono text-neutral-400 flex items-center gap-1">
                    <Terminal className="w-3 h-3 text-indigo-400" />
                    Agent Analytical Reasoning:
                  </span>
                  <div className="p-3 rounded-lg bg-black/60 border border-white/10 text-[11px] text-neutral-300 leading-relaxed font-sans max-h-36 overflow-y-auto">
                    {selectedIncident.reasoning}
                  </div>
                </div>

                {/* ── Recommended Action ── */}
                <div className="space-y-1.5">
                  <span className="text-[10px] uppercase tracking-wider font-mono text-neutral-400 flex items-center gap-1">
                    <Zap className="w-3 h-3 text-amber-400" />
                    Prescribed Remediation:
                  </span>
                  <div className="p-2.5 rounded-lg bg-amber-950/20 border border-amber-500/20 text-[11px] text-amber-200/90 leading-relaxed font-sans">
                    {selectedIncident.recommended_action}
                  </div>
                </div>

                {/* ── Large "Approve Action" Button for High-Risk Threats ── */}
                {isStagedForApproval && (
                  <button
                    onClick={() => handleApproveAction(selectedIncident.incident_id)}
                    disabled={isApproving}
                    className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-orange-600 via-red-600 to-pink-600 hover:from-orange-500 hover:via-red-500 hover:to-pink-500 text-white font-bold text-xs uppercase tracking-wider transition-all duration-200 shadow-[0_0_20px_rgba(249,115,22,0.4)] hover:shadow-[0_0_25px_rgba(249,115,22,0.6)] active:scale-[0.98] disabled:opacity-50 flex items-center justify-center gap-2 mt-4"
                  >
                    {isApproving ? (
                      <div className="flex items-center gap-2">
                        <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                        <span>Transmitting Approval...</span>
                      </div>
                    ) : (
                      <>
                        <ShieldCheck className="w-4 h-4" />
                        <span>Approve Action & Mitigate</span>
                      </>
                    )}
                  </button>
                )}
              </>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-center p-6 text-neutral-600">
                <Brain className="w-10 h-10 mb-2 stroke-[1.2] text-neutral-600" />
                <p className="text-xs font-medium text-neutral-400">Agent Idle</p>
                <p className="text-[10px] text-neutral-600 mt-1">
                  Select an event to view full LLM triage findings, risk scoring, and mitigation options.
                </p>
              </div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
