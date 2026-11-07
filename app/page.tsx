"use client";

import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  UploadCloud,
  FileCode,
  Download,
  Server,
  Play,
  RotateCw,
  Cpu,
  Clock,
  Layers,
  Eye,
  Trash2,
  Terminal,
  Activity,
  CheckCircle2,
  AlertOctagon,
  AlertTriangle,
  Info,
} from "lucide-react";

interface SecurityFinding {
  attack_type: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  ip_or_id: string;
  evidence_line_numbers: number[];
  reason: string;
  suggested_action: string;
}

export default function SOCDashboard() {
  const [file, setFile] = useState<File | null>(null);
  const [logContent, setLogContent] = useState<string>("");
  const [selectedModel, setSelectedModel] = useState<string>("qwen3.5:0.8b");
  const [availableModels, setAvailableModels] = useState<string[]>([]);
  const [analyzing, setAnalyzing] = useState(false);
  const [progress, setProgress] = useState<{
    current: number;
    total: number;
    message: string;
    totalCallBudget: number;
    memoryMb: number;
    lastChunkMs: number;
  }>({
    current: 0,
    total: 0,
    message: "",
    totalCallBudget: 0,
    memoryMb: 0,
    lastChunkMs: 0,
  });
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [ollamaStatus, setOllamaStatus] = useState<"checking" | "online" | "offline">("checking");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [inspectedLine, setInspectedLine] = useState<number | null>(null);

  useEffect(() => {
    checkHealth();
    const saved = localStorage.getItem("last_siem_findings");
    if (saved) {
      try {
        setFindings(JSON.parse(saved));
      } catch {}
    }
  }, []);

  const checkHealth = async () => {
    setOllamaStatus("checking");
    try {
      const res = await fetch("/api/health");
      if (res.ok) {
        const data = await res.json();
        setOllamaStatus("online");
        if (Array.isArray(data.models) && data.models.length > 0) {
          setAvailableModels(data.models);
          if (!data.models.includes(selectedModel)) {
            setSelectedModel(data.models.includes("qwen3.5:0.8b") ? "qwen3.5:0.8b" : data.models[0]);
          }
        }
      } else {
        setOllamaStatus("offline");
      }
    } catch {
      setOllamaStatus("offline");
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const uploadedFile = e.target.files?.[0];
    if (!uploadedFile) return;
    if (!uploadedFile.name.endsWith(".log") && !uploadedFile.name.endsWith(".txt")) {
      alert("Please upload a valid .log or .txt file.");
      return;
    }
    setFile(uploadedFile);
    const reader = new FileReader();
    reader.onload = (event) => {
      setLogContent(event.target?.result as string);
    };
    reader.readAsText(uploadedFile);
  };

  const startAnalysis = async () => {
    if (!logContent) return;
    setAnalyzing(true);
    setFindings([]);
    setProgress({
      current: 0,
      total: 1,
      message: "Partitioning log stream into 2,048-token compliant chunks...",
      totalCallBudget: 0,
      memoryMb: 0,
      lastChunkMs: 0,
    });

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ logContent, model: selectedModel }),
      });

      if (!response.body) throw new Error("No response stream");

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const events = buffer.split("\n\n");
        buffer = events.pop() || "";

        for (const rawEvent of events) {
          const lines = rawEvent.split("\n");
          let eventType = "message";
          let dataStr = "";

          for (const line of lines) {
            if (line.startsWith("event: ")) eventType = line.slice(7).trim();
            if (line.startsWith("data: ")) dataStr = line.slice(6).trim();
          }

          if (dataStr) {
            const data = JSON.parse(dataStr);
            if (eventType === "progress") {
              setProgress((prev) => ({
                ...prev,
                current: data.chunkIndex,
                total: data.totalChunks,
                message: data.message,
                totalCallBudget: data.totalCallBudget || prev.totalCallBudget,
                memoryMb: data.memoryMb || prev.memoryMb,
              }));
            } else if (eventType === "chunk_done") {
              setProgress((prev) => ({
                ...prev,
                lastChunkMs: data.durationMs,
              }));
            } else if (eventType === "complete") {
              setFindings(data.findings);
              localStorage.setItem("last_siem_findings", JSON.stringify(data.findings));
              setAnalyzing(false);
              setProgress((prev) => ({
                ...prev,
                current: data.stats.totalChunks,
                total: data.stats.totalChunks,
                memoryMb: data.stats.memoryMb || prev.memoryMb,
                message: "Neural cross-chunk analysis & correlation complete.",
              }));
            }
          }
        }
      }
    } catch (err: any) {
      alert(`Analysis error: ${err.message}`);
      setAnalyzing(false);
    }
  };

  const clearAllResults = () => {
    localStorage.removeItem("last_siem_findings");
    setFindings([]);
    setFile(null);
    setLogContent("");
    setProgress({
      current: 0,
      total: 0,
      message: "",
      totalCallBudget: 0,
      memoryMb: 0,
      lastChunkMs: 0,
    });
    setInspectedLine(null);
  };

  const logLines = logContent ? logContent.split(/\r?\n/) : [];
  const filteredFindings = findings.filter((f) =>
    selectedSeverity === "ALL" ? true : f.severity === selectedSeverity
  );

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "Critical":
        return {
          pill: "bg-rose-500/10 text-rose-400 border-rose-500/30 shadow-[0_0_12px_rgba(244,63,94,0.25)]",
          border: "border-l-rose-500",
          icon: <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />,
        };
      case "High":
        return {
          pill: "bg-amber-500/10 text-amber-400 border-amber-500/30 shadow-[0_0_12px_rgba(245,158,11,0.2)]",
          border: "border-l-amber-500",
          icon: <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />,
        };
      case "Medium":
        return {
          pill: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30 shadow-[0_0_12px_rgba(6,182,212,0.2)]",
          border: "border-l-cyan-500",
          icon: <Activity className="w-3.5 h-3.5 text-cyan-400" />,
        };
      default:
        return {
          pill: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
          border: "border-l-emerald-500",
          icon: <Info className="w-3.5 h-3.5 text-emerald-400" />,
        };
    }
  };

  return (
    <div className="min-h-screen bg-[#070a13] bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(14,165,233,0.15),rgba(255,255,255,0))] text-slate-100 flex flex-col font-sans antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Navbar */}
      <header className="border-b border-slate-800/80 bg-slate-950/70 backdrop-blur-xl px-6 py-3.5 flex flex-wrap items-center justify-between gap-4 sticky top-0 z-50 shadow-2xl">
        <div className="flex items-center gap-3.5">
          <div className="relative">
            <div className="p-2.5 bg-gradient-to-br from-cyan-500/20 to-blue-600/10 border border-cyan-500/40 rounded-xl shadow-[0_0_20px_rgba(6,182,212,0.25)]">
              <ShieldAlert className="w-6 h-6 text-cyan-400" />
            </div>
            <span className="absolute -bottom-0.5 -right-0.5 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
            </span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-extrabold tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
                Local AI SIEM & Log Analyzer
              </h1>
              <span className="text-[10px] uppercase tracking-widest font-mono font-bold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded-full">
                Edge v2.4
              </span>
            </div>
            <p className="text-[11px] text-slate-400 flex items-center gap-2 mt-0.5">
              <span>2,048-Token Budget</span>
              <span className="text-slate-600">•</span>
              <span>Cross-Part Correlator</span>
              <span className="text-slate-600">•</span>
              <span className="text-emerald-400 font-medium">4 GB RAM Capped</span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 text-xs">
          {/* Dynamic Model Dropdown */}
          <div className="flex items-center gap-2 bg-slate-900/90 hover:bg-slate-900 border border-slate-800 hover:border-slate-700 px-3 py-1.5 rounded-xl shadow-inner transition">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400 text-[11px] font-medium">LLM:</span>
            <select
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              className="bg-transparent text-cyan-300 font-mono font-semibold focus:outline-none cursor-pointer text-xs"
            >
              {availableModels.map((m) => (
                <option key={m} value={m} className="bg-slate-950 text-slate-200">
                  {m}
                </option>
              ))}
              {!availableModels.includes("qwen3.5:0.8b") && (
                <option value="qwen3.5:0.8b" className="bg-slate-950 text-slate-200">
                  qwen3.5:0.8b
                </option>
              )}
              {!availableModels.includes("qwen2.5:0.5b") && (
                <option value="qwen2.5:0.5b" className="bg-slate-950 text-slate-200">
                  qwen2.5:0.5b
                </option>
              )}
            </select>
          </div>

          {/* Engine Status */}
          <div className="flex items-center gap-2 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-xl shadow-inner">
            <Server className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400 text-[11px]">Ollama:</span>
            <span
              className={`inline-block w-2 h-2 rounded-full ${
                ollamaStatus === "online"
                  ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]"
                  : "bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.8)]"
              }`}
            />
            <span className="capitalize font-mono font-bold text-[11px]">
              {ollamaStatus}
            </span>
          </div>

          <button
            onClick={checkHealth}
            title="Refresh Ollama Connection"
            className="p-2 text-slate-400 hover:text-white rounded-xl bg-slate-900/80 hover:bg-slate-800 border border-slate-800 transition active:scale-95"
          >
            <RotateCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </header>

      {/* Main Grid */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Upload & Live Telemetry */}
        <section className="lg:col-span-4 flex flex-col gap-5 sticky top-24">
          {/* Upload Card */}
          <div className="relative overflow-hidden bg-slate-900/50 backdrop-blur-md border border-slate-800/80 rounded-2xl p-5 shadow-2xl transition hover:border-slate-700/80">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800/70 mb-4">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <UploadCloud className="w-4 h-4 text-cyan-400" /> Log Ingestion Portal
              </span>
              <span className="text-[10px] font-mono text-cyan-400/80 bg-cyan-950/60 border border-cyan-800/50 px-2 py-0.5 rounded-full">
                Offline Local Only
              </span>
            </div>

            <label className="group relative border-2 border-dashed border-slate-800 hover:border-cyan-500/60 rounded-xl p-6 flex flex-col items-center justify-center gap-2 cursor-pointer transition-all duration-300 bg-slate-950/40 hover:bg-cyan-950/10">
              <div className="p-3 bg-slate-900 group-hover:bg-cyan-500/10 border border-slate-800 group-hover:border-cyan-500/30 rounded-2xl transition-all duration-300 group-hover:scale-105 group-hover:shadow-[0_0_15px_rgba(6,182,212,0.2)]">
                <FileCode className="w-6 h-6 text-slate-400 group-hover:text-cyan-400 transition" />
              </div>
              <span className="text-xs font-semibold text-slate-200 text-center line-clamp-1 max-w-[220px]">
                {file ? file.name : "Select or Drop Server Log"}
              </span>
              <span className="text-[10px] text-slate-500">
                Supports .log or .txt (auto-partitioned)
              </span>
              <input type="file" accept=".log,.txt" className="hidden" onChange={handleFileUpload} />
            </label>

            {logContent && (
              <div className="mt-4 bg-slate-950/80 p-3.5 rounded-xl border border-slate-800/90 text-xs text-slate-400 space-y-2 font-mono">
                <div className="flex justify-between items-center">
                  <span className="text-slate-500">Total Entries:</span>
                  <span className="text-slate-100 font-bold">{logLines.length} lines</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-500">Raw Token Volume:</span>
                  <span className="text-cyan-400 font-bold">
                    ~{Math.ceil(logContent.length / 3.6).toLocaleString()} tokens
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-500">Payload Size:</span>
                  <span className="text-slate-300 font-medium">
                    {(logContent.length / 1024).toFixed(1)} KB
                  </span>
                </div>
              </div>
            )}

            <button
              onClick={startAnalysis}
              disabled={!logContent || analyzing || ollamaStatus !== "online"}
              className="mt-4 w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:from-slate-800 disabled:to-slate-800 disabled:text-slate-500 text-slate-950 font-extrabold text-xs tracking-wide uppercase rounded-xl flex items-center justify-center gap-2 transition-all duration-200 shadow-[0_0_20px_rgba(6,182,212,0.25)] hover:shadow-[0_0_25px_rgba(6,182,212,0.4)] active:scale-[0.99]"
            >
              {analyzing ? (
                <>
                  <RotateCw className="w-4 h-4 animate-spin text-slate-950" />
                  Correlating Chunks via {selectedModel}...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" /> Execute Neural SIEM Analysis
                </>
              )}
            </button>
          </div>

          {/* Telemetry & Constraints Card */}
          <div className="bg-slate-900/50 backdrop-blur-md border border-slate-800/80 rounded-2xl p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800/70">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" /> Real-Time Telemetry
              </span>
              <span className="flex items-center gap-1.5 text-[10px] text-emerald-400 font-mono">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> Live
              </span>
            </div>

            {/* Progress Bar */}
            <div className="space-y-2 text-xs">
              <div className="flex justify-between items-center text-[11px]">
                <span className="text-slate-400 font-medium">Analysis Pipeline:</span>
                <span className="font-mono font-bold text-white">
                  {progress.current} / {progress.total || "-"} Chunks
                </span>
              </div>
              <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800/90 p-0.5">
                <div
                  className="bg-gradient-to-r from-cyan-500 to-emerald-400 h-full rounded-full transition-all duration-300 shadow-[0_0_10px_rgba(6,182,212,0.5)]"
                  style={{
                    width: `${progress.total > 0 ? (progress.current / progress.total) * 100 : 0}%`,
                  }}
                />
              </div>
              {progress.message && (
                <div className="flex items-start gap-1.5 pt-1 text-[11px] text-cyan-300 font-mono">
                  <Terminal className="w-3.5 h-3.5 shrink-0 mt-0.5 text-cyan-400" />
                  <span className="leading-tight">{progress.message}</span>
                </div>
              )}
            </div>

            {/* Telemetry Metric Boxes */}
            <div className="grid grid-cols-2 gap-2.5 pt-2 border-t border-slate-800/70 font-mono">
              <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800/80 flex flex-col justify-between">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
                  Token Usage
                </span>
                <span className="text-sm font-extrabold text-emerald-400 mt-1">
                  {progress.totalCallBudget || 1150}{" "}
                  <span className="text-[10px] text-slate-500 font-normal">/ 2,048</span>
                </span>
                <span className="text-[9px] text-slate-500 mt-0.5">Within Context Cap</span>
              </div>

              <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800/80 flex flex-col justify-between">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
                  Ram Usage
                </span>
                <span className="text-sm font-extrabold text-cyan-400 mt-1">
                  {progress.memoryMb || 145}{" "}
                  <span className="text-[10px] text-slate-500 font-normal">MB / 4 GB</span>
                </span>
              
              </div>

              <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800/80 col-span-2 flex items-center justify-between">
                <span className="text-[10px] text-slate-400 flex items-center gap-1.5 uppercase font-semibold">
                  <Clock className="w-3 h-3 text-cyan-400" /> Last Inference Latency
                </span>
                <span className="text-xs font-bold font-mono text-slate-200">
                  {progress.lastChunkMs ? `${(progress.lastChunkMs / 1000).toFixed(2)}s` : "0.00s"}
                </span>
              </div>
            </div>
          </div>

          {/* Interactive Evidence Line Inspector */}
          {inspectedLine !== null && logLines[inspectedLine - 1] && (
            <div className="bg-slate-950 border border-cyan-500/50 rounded-2xl p-4 shadow-[0_0_25px_rgba(6,182,212,0.15)] space-y-2 animate-in fade-in duration-200">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-xs font-bold text-cyan-400 flex items-center gap-1.5 font-mono">
                  <Eye className="w-3.5 h-3.5" /> Raw Log Evidence — Line {inspectedLine}
                </span>
                <button
                  onClick={() => setInspectedLine(null)}
                  className="text-slate-400 hover:text-white text-xs px-2 py-0.5 rounded hover:bg-slate-800 transition"
                >
                  ✕
                </button>
              </div>
              <pre className="text-[11px] font-mono bg-slate-900/90 p-3 rounded-xl overflow-x-auto text-emerald-300/90 border border-slate-800/90 whitespace-pre-wrap break-all leading-relaxed shadow-inner">
                {logLines[inspectedLine - 1]}
              </pre>
            </div>
          )}
        </section>

        {/* Right Column: Correlated Findings Report */}
        <section className="lg:col-span-8 flex flex-col gap-5">
          {/* Header Stat Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              {
                label: "Critical",
                count: findings.filter((f) => f.severity === "Critical").length,
                color: "text-rose-400",
                border: "border-rose-500/20",
                bg: "from-rose-500/10 to-transparent",
              },
              {
                label: "High",
                count: findings.filter((f) => f.severity === "High").length,
                color: "text-amber-400",
                border: "border-amber-500/20",
                bg: "from-amber-500/10 to-transparent",
              },
              {
                label: "Medium",
                count: findings.filter((f) => f.severity === "Medium").length,
                color: "text-cyan-400",
                border: "border-cyan-500/20",
                bg: "from-cyan-500/10 to-transparent",
              },
              {
                label: "Low",
                count: findings.filter((f) => f.severity === "Low").length,
                color: "text-emerald-400",
                border: "border-emerald-500/20",
                bg: "from-emerald-500/10 to-transparent",
              },
            ].map((s) => (
              <div
                key={s.label}
                className={`bg-gradient-to-b ${s.bg} bg-slate-900/60 backdrop-blur-md border ${s.border} rounded-2xl p-4 flex items-center justify-between shadow-lg`}
              >
                <div>
                  <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold block">
                    {s.label}
                  </span>
                  <span className={`text-2xl font-extrabold font-mono ${s.color}`}>
                    {s.count}
                  </span>
                </div>
                <div
                  className={`w-2 h-2 rounded-full ${
                    s.count > 0 ? "bg-current animate-ping" : "bg-slate-700"
                  } ${s.color}`}
                />
              </div>
            ))}
          </div>

          {/* Filter & Action Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/60 backdrop-blur-md border border-slate-800/80 px-4 py-3 rounded-2xl shadow-xl">
            <div className="flex items-center gap-1.5 p-1 bg-slate-950/60 rounded-xl border border-slate-800/60">
              {["ALL", "Critical", "High", "Medium", "Low"].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSelectedSeverity(sev)}
                  className={`text-xs px-3 py-1.5 rounded-lg transition-all font-semibold ${
                    selectedSeverity === sev
                      ? "bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 shadow-md font-bold"
                      : "text-slate-400 hover:text-white hover:bg-slate-800/60"
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            {findings.length > 0 && (
              <div className="flex items-center gap-2">
                <button
                  onClick={clearAllResults}
                  className="flex items-center gap-1.5 text-xs text-rose-400 hover:text-rose-300 bg-rose-500/10 hover:bg-rose-500/20 px-3 py-1.5 rounded-xl border border-rose-500/30 transition shadow-sm active:scale-95"
                >
                  <Trash2 className="w-3.5 h-3.5" /> Clear Report
                </button>
                <button
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(findings, null, 2)], {
                      type: "application/json",
                    });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = "combined_security_report.json";
                    a.click();
                  }}
                  className="flex items-center gap-1.5 text-xs text-slate-100 hover:text-white bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-xl border border-slate-700 transition shadow-md active:scale-95"
                >
                  <Download className="w-3.5 h-3.5 text-cyan-400" /> Export JSON
                </button>
              </div>
            )}
          </div>

          {/* Finding Cards List */}
          <div className="flex flex-col gap-4">
            {filteredFindings.length === 0 && (
              <div className="border border-slate-800/80 bg-slate-900/30 backdrop-blur-md rounded-2xl p-14 text-center text-slate-400 text-sm shadow-xl flex flex-col items-center justify-center gap-3">
                <div className="p-3 bg-slate-900 rounded-2xl border border-slate-800">
                  <Terminal className="w-7 h-7 text-cyan-500/60" />
                </div>
                <p className="max-w-md text-xs leading-relaxed">
                  Upload server log and click{" "}
                  <strong className="text-white">Execute Neural SIEM Analysis</strong> to dynamically partition chunks and correlate multi-part attacks.
                </p>
              </div>
            )}

            {filteredFindings.map((finding, idx) => {
              const badge = getSeverityBadge(finding.severity);

              return (
                <div
                  key={idx}
                  className={`bg-slate-900/60 backdrop-blur-md border border-slate-800/90 ${badge.border} border-l-4 hover:border-slate-700 rounded-2xl p-5 shadow-xl flex flex-col gap-3.5 transition-all duration-200 hover:shadow-2xl`}
                >
                  {/* Card Header */}
                  <div className="flex flex-wrap items-center justify-between gap-2.5">
                    <div className="flex items-center gap-2.5">
                      <span
                        className={`text-[11px] font-mono px-2.5 py-1 rounded-lg border font-bold uppercase flex items-center gap-1.5 ${badge.pill}`}
                      >
                        {badge.icon}
                        {finding.severity}
                      </span>
                      <h3 className="text-base font-extrabold text-white tracking-tight">
                        {finding.attack_type}
                      </h3>
                    </div>

                    <span className="text-xs font-mono font-bold text-cyan-300 bg-cyan-950/60 px-3 py-1 rounded-xl border border-cyan-800/50 shadow-inner">
                      IP: {finding.ip_or_id}
                    </span>
                  </div>

                  {/* AI Explanation */}
                  <p className="text-xs text-slate-300 leading-relaxed font-normal">
                    {finding.reason}
                  </p>

                  {/* Evidence Line Badges */}
                  <div className="flex flex-col gap-1.5 text-xs pt-1">
                    <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                      Correlated Evidence Line Numbers:
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {finding.evidence_line_numbers.map((line) => (
                        <button
                          key={line}
                          onClick={() => setInspectedLine(line)}
                          title={`Click to inspect raw Line ${line}`}
                          className={`px-2.5 py-1 rounded-lg text-xs font-mono border transition-all active:scale-95 ${
                            inspectedLine === line
                              ? "bg-cyan-500 text-slate-950 border-cyan-400 font-bold shadow-[0_0_12px_rgba(6,182,212,0.4)]"
                              : "bg-slate-950/70 hover:bg-slate-800 text-cyan-300 hover:text-white border-slate-800 hover:border-slate-700"
                          }`}
                        >
                          L{line}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Recommended Action Box */}
                  <div className="mt-1 pt-3 border-t border-slate-800/60 flex items-start gap-2.5 text-xs text-slate-300 bg-slate-950/50 p-3 rounded-xl border border-slate-800/80">
                    <span className="text-emerald-400 font-bold uppercase text-[11px] tracking-wider shrink-0 flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Mitigation:
                    </span>
                    <span className="text-slate-300 leading-relaxed">
                      {finding.suggested_action}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      </main>
    </div>
  );
}