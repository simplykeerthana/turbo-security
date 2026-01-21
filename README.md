# turbo-security

import React, { useState } from 'react';
import { 
  Monitor, Database, MessageSquare, Terminal, Layers, Activity, ArrowRight, Box, Code, 
  Settings, AlertTriangle, Globe, Shield, Lock, Eye, FileWarning, Network, Layout, 
  List, ScanLine, Bug, Sparkles, Brain, User, Server
} from 'lucide-react';

// ==========================================
// 1. DATA & CONSTANTS
// ==========================================

const THREATS = [
  // Server Threats (S01-S10)
  { 
    id: "S01", title: "Prompt Injection", csa_ref: "MCP-S01", scope: "server", isAiNative: true, detection_type: "Runtime", icon: <Terminal className="w-4 h-4 text-red-600" />,
    description: "Adversarial inputs overriding System Prompt.", mitigation: "Runtime: Context Segregation",
    ast_rule: "Detect concatenation of unverified user input into 'system_prompt' variables.",
    llm_rule: "Chain-of-Thought Monitoring: Watch for agent internal monologue stating 'I must ignore rules' or sudden role shifts."
  },
  { 
    id: "S02", title: "Confused Deputy", csa_ref: "MCP-S02", scope: "server", isAiNative: true, detection_type: "Runtime", icon: <User className="w-4 h-4 text-orange-600" />,
    description: "AI tricked into privileged actions.", mitigation: "Runtime: Verify user_id per call",
    ast_rule: "Flag tool execution paths missing 'user_id' or 'session_token' checks.",
    llm_rule: "Intent Verification: Compare the high-level user prompt (e.g. 'check balance') with low-level tool call (e.g. 'transfer_money')."
  },
  { 
    id: "S03", title: "Tool Poisoning", csa_ref: "MCP-S03", scope: "server", isAiNative: true, detection_type: "Static", icon: <FileWarning className="w-4 h-4 text-red-500" />,
    description: "Hidden Instructions or Permissive Schemas in tool metadata.", mitigation: "Static: Scan descriptions",
    ast_rule: "Lint 'description' fields for hidden text (white-on-white) or instructions like 'ignore safety'.",
    llm_rule: "Semantic Analysis: Verify if the tool schema allows broader actions (e.g. {admin: true}) than the description implies."
  },
  { 
    id: "S04", title: "Credential Exposure", csa_ref: "MCP-S04", scope: "server", isAiNative: false, detection_type: "Static", icon: <Lock className="w-4 h-4 text-yellow-500" />,
    description: "API keys in logs.", mitigation: "Static: Regex scan",
    ast_rule: "Regex scan for high-entropy strings in logging statements (console.log).",
    llm_rule: "Context-aware analysis of variable names to find obfuscated secrets."
  },
  { 
    id: "S05", title: "Insecure Config", csa_ref: "MCP-S05", scope: "server", isAiNative: false, detection_type: "Static", icon: <Server className="w-4 h-4 text-gray-500" />,
    description: "Weak defaults.", mitigation: "Static: Lint config",
    ast_rule: "JSON linting for default passwords, '0.0.0.0' bindings, or missing auth.",
    llm_rule: "Analyze config comments for non-standard security deviations."
  },
  { 
    id: "S06", title: "Supply Chain", csa_ref: "MCP-S06", scope: "server", isAiNative: false, detection_type: "Static", icon: <Database className="w-4 h-4 text-pink-600" />,
    description: "Compromised dependencies or updates.", mitigation: "Static: Dependency pinning",
    ast_rule: "SCA analysis of package.json for known malicious versions.",
    llm_rule: "Sentiment analysis of recent dependency commit messages for anomalies."
  },
  { 
    id: "S07", title: "Excessive Agency", csa_ref: "MCP-S07", scope: "server", isAiNative: true, detection_type: "Static", icon: <Shield className="w-4 h-4 text-blue-500" />,
    description: "Granting broad permissions to AI.", mitigation: "Static: Least Privilege",
    ast_rule: "Map requested API scopes vs. actual API calls used in code.",
    llm_rule: "Outcome Simulation: Simulating the 'worst case' tool chain execution to see if it violates safety policies."
  },
  { 
    id: "S08", title: "Data Exfiltration", csa_ref: "MCP-S08", scope: "server", isAiNative: false, detection_type: "Runtime", icon: <Activity className="w-4 h-4 text-purple-500" />,
    description: "Unauthorized data egress.", mitigation: "Runtime: Network filtering",
    ast_rule: "Detect usage of fetch/axios with user-controlled URLs.",
    llm_rule: "Monitor outgoing payloads for sensitive PII/context data."
  },
  { 
    id: "S09", title: "Context Spoofing", csa_ref: "MCP-S09", scope: "server", isAiNative: true, detection_type: "Runtime", icon: <Eye className="w-4 h-4 text-indigo-500" />,
    description: "Fake context injected to bias model.", mitigation: "Runtime: Sign context sources",
    ast_rule: "Check for missing signature verification on resource loaders.",
    llm_rule: "Consistency Check: Detect if file content contradicts its metadata (e.g. .txt file containing executable binary headers)."
  },
  { 
    id: "S10", title: "Insecure Transport", csa_ref: "MCP-S10", scope: "server", isAiNative: false, detection_type: "Net Scan", icon: <Globe className="w-4 h-4 text-teal-600" />,
    description: "Unencrypted HTTP.", mitigation: "Network: Scan endpoints",
    ast_rule: "Detect 'http://' literals or disabled TLS verification flags.",
    llm_rule: "N/A (Structural vulnerability)."
  },

  // Client Threats (C01-C10)
  { 
    id: "C01", title: "Malicious Connection", csa_ref: "MCP-C01", scope: "client", isAiNative: false, detection_type: "Runtime", icon: <Network className="w-4 h-4 text-red-500" />,
    description: "Connecting to fake servers.", mitigation: "Runtime: Allow-lists",
    ast_rule: "Check for missing URL validation logic in connection handler.",
    llm_rule: "Analyze server handshake responses for social engineering cues."
  },
  { 
    id: "C02", title: "Insecure Storage", csa_ref: "MCP-C02", scope: "client", isAiNative: false, detection_type: "Static", icon: <Lock className="w-4 h-4 text-orange-500" />,
    description: "Plaintext keys on client.", mitigation: "Static: Config scan",
    ast_rule: "Scan client config files for plaintext API keys.",
    llm_rule: "N/A"
  },
  { 
    id: "C03", title: "UI/UX Deception", csa_ref: "MCP-C03", scope: "client", isAiNative: true, detection_type: "Audit", icon: <Layout className="w-4 h-4 text-yellow-600" />,
    description: "AI hiding actions behind vague UI.", mitigation: "Audit: Compare prompts vs actions",
    ast_rule: "Verify tool names match the strings displayed in UI components.",
    llm_rule: "Compare tool side-effects description vs. UI text shown to user (e.g. Tool: 'Delete File', UI: 'Optimizing storage')."
  },
  { 
    id: "C04", title: "Insufficient Validation", csa_ref: "MCP-C04", scope: "client", isAiNative: false, detection_type: "Runtime", icon: <Shield className="w-4 h-4 text-gray-500" />,
    description: "No server cert check.", mitigation: "Runtime: Require mTLS",
    ast_rule: "Detect 'rejectUnauthorized: false' in HTTP client config.",
    llm_rule: "N/A"
  },
  { 
    id: "C05", title: "Client Leakage", csa_ref: "MCP-C05", scope: "client", isAiNative: false, detection_type: "Static", icon: <FileWarning className="w-4 h-4 text-blue-400" />,
    description: "Sensitive logs on client.", mitigation: "Static: Check log levels",
    ast_rule: "Check logging configuration levels (ensure DEBUG is off).",
    llm_rule: "Scan client-side logs for inadvertent prompt leakage."
  },
  { 
    id: "C06", title: "Unconstrained Auth", csa_ref: "MCP-C06", scope: "client", isAiNative: true, detection_type: "Static", icon: <User className="w-4 h-4 text-purple-600" />,
    description: "Users training AI to 'Always Allow'.", mitigation: "Static: Policy Review",
    ast_rule: "Review 'permissions.json' for wildcard (*) allow rules.",
    llm_rule: "Analyze user behavior patterns for 'fatigue-based' approvals."
  },
  { 
    id: "C07", title: "Malicious Output", csa_ref: "MCP-C07", scope: "client", isAiNative: true, detection_type: "Runtime", icon: <Code className="w-4 h-4 text-red-600" />,
    description: "AI generating malicious executable code.", mitigation: "Runtime: Sandbox renderer",
    ast_rule: "Detect usage of 'eval()', 'exec()', or 'innerHTML' on response data.",
    llm_rule: "Adversarial Perturbation Check: Scan outputs for hidden/homoglyph characters designed to bypass renderers."
  },
  { 
    id: "C08", title: "Insecure Comm", csa_ref: "MCP-C08", scope: "client", isAiNative: false, detection_type: "Net Scan", icon: <Globe className="w-4 h-4 text-teal-600" />,
    description: "Weak TLS on client.", mitigation: "Network: SSL Labs test",
    ast_rule: "Audit TLS version settings in client network stack.",
    llm_rule: "N/A"
  },
  { 
    id: "C09", title: "Session Failure", csa_ref: "MCP-C09", scope: "client", isAiNative: false, detection_type: "Runtime", icon: <Activity className="w-4 h-4 text-indigo-500" />,
    description: "Session hijacking.", mitigation: "Runtime: Rotate tokens",
    ast_rule: "Check for infinite session timeouts in config.",
    llm_rule: "Detect anomalous session usage patterns (e.g. rapid geo-hopping)."
  },
  { 
    id: "C10", title: "Update Mgmt", csa_ref: "MCP-C10", scope: "client", isAiNative: false, detection_type: "Audit", icon: <Bug className="w-4 h-4 text-green-600" />,
    description: "Delayed patches.", mitigation: "Audit: Signed binaries",
    ast_rule: "Check update mechanism for signature verification logic.",
    llm_rule: "N/A"
  },
];

// ==========================================
// 2. SUB-COMPONENTS (Architecture)
// ==========================================

const ParticipantsView = ({ selectedNode, setSelectedNode }) => (
  <div className="min-w-[800px] min-h-[500px] w-full h-full p-8 flex items-center justify-center relative">
    {/* HOST BLOCK (AI DRIVEN) */}
    <div 
      className={`absolute left-10 top-1/2 -translate-y-1/2 w-64 h-96 bg-indigo-50 border-2 ${selectedNode === 'host' ? 'border-indigo-500 ring-2 ring-indigo-200' : 'border-indigo-200'} rounded-xl p-4 transition-all cursor-pointer z-10 shadow-sm hover:shadow-md group`}
      onClick={() => setSelectedNode('host')}
    >
      <div className="absolute -top-3 left-4 bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded-full text-[10px] font-bold border border-indigo-200 flex items-center gap-1">
        <Sparkles size={10} /> AI Agent
      </div>
      <div className="flex items-center gap-2 text-indigo-900 font-bold mb-4 mt-2">
        <Brain size={20} /> MCP Host
      </div>
      <div className="text-xs text-indigo-700 mb-6">
        The Intelligence Layer (Claude / IDE). Orchestrates context and tools.
      </div>

      {/* Clients Container */}
      <div className="space-y-4">
        <div className="bg-white border-2 border-indigo-200 border-dashed rounded-lg p-3 flex items-center gap-3">
          <div className="bg-slate-100 p-2 rounded">
            <Activity size={16} className="text-slate-600" />
          </div>
          <div>
            <div className="text-xs font-bold text-slate-700">MCP Client 1</div>
            <div className="text-[10px] text-slate-500">Connection Mgr</div>
          </div>
        </div>
      </div>
    </div>

    {/* CONNECTIONS */}
    <svg className="absolute inset-0 w-full h-full pointer-events-none">
      {/* Stdio (Red) */}
      <path d="M 320,250 C 450,250 450,180 580,180" fill="none" stroke="#ef4444" strokeWidth="2" strokeDasharray="5,5" />
      <rect x="400" y="195" width="70" height="20" fill="#fef2f2" rx="4" />
      <text x="435" y="209" textAnchor="middle" fontSize="10" fill="#b91c1c" fontWeight="bold" fontFamily="monospace">Stdio Pipe</text>

      {/* HTTP (Green) */}
      <path d="M 320,350 C 450,350 450,420 580,420" fill="none" stroke="#10b981" strokeWidth="2" strokeDasharray="5,5" />
      <rect x="400" y="385" width="70" height="20" fill="#ecfdf5" rx="4" />
      <text x="435" y="399" textAnchor="middle" fontSize="10" fill="#047857" fontWeight="bold" fontFamily="monospace">SSE / HTTP</text>
    </svg>

    {/* SERVERS (Deterministic) */}
    <div className="absolute right-20 top-20 w-64 h-40 bg-slate-100 border-2 border-slate-300 rounded-lg p-4 shadow-sm hover:border-slate-400 transition-colors z-10">
      <div className="absolute -top-3 left-4 bg-slate-200 text-slate-600 px-2 py-0.5 rounded-full text-[10px] font-bold border border-slate-300">
         Deterministic
      </div>
      <div className="flex items-center gap-2 text-slate-700 font-bold mb-1 mt-2">
        <Terminal size={18} /> Local Server
      </div>
      <div className="text-[10px] text-slate-500 mb-2 font-mono">Filesystem / SQLite</div>
      <div className="text-xs bg-white p-2 rounded border border-slate-200 text-slate-600">
        Executes rigid logic. No AI "thinking" here.
      </div>
    </div>

    <div className="absolute right-20 bottom-20 w-64 h-40 bg-slate-100 border-2 border-slate-300 rounded-lg p-4 shadow-sm hover:border-slate-400 transition-colors z-10">
      <div className="absolute -top-3 left-4 bg-slate-200 text-slate-600 px-2 py-0.5 rounded-full text-[10px] font-bold border border-slate-300">
         Deterministic
      </div>
      <div className="flex items-center gap-2 text-slate-700 font-bold mb-1 mt-2">
        <Database size={18} /> Remote Server
      </div>
      <div className="text-[10px] text-slate-500 mb-2 font-mono">Sentry / GitHub</div>
      <div className="text-xs bg-white p-2 rounded border border-slate-200 text-slate-600">
         Provides API data to the AI context window.
      </div>
    </div>

    {selectedNode === 'host' && (
      <div className="absolute bottom-6 left-1/2 -translate-x-1/2 bg-indigo-900 text-white p-4 rounded-lg shadow-xl w-96 animate-in fade-in slide-in-from-bottom-2 z-20">
        <h3 className="font-bold text-sm mb-2 flex items-center gap-2"><Sparkles size={14}/> The AI Coordinator</h3>
        <p className="text-xs leading-relaxed text-indigo-100">
          The Host uses an LLM to decide <strong>which tools</strong> to call based on user intent. This is the probabilistic "brain" of the operation.
        </p>
      </div>
    )}
  </div>
);

const LayersView = () => (
  <div className="min-w-[600px] w-full h-full p-8 flex flex-col items-center justify-center gap-8">
    <div className="w-full max-w-2xl bg-slate-100 border-2 border-slate-300 border-dashed rounded-xl p-8 relative">
      <div className="absolute -top-3 left-6 bg-slate-200 px-3 py-1 rounded text-xs font-bold text-slate-600 uppercase tracking-wider">
        Outer Layer: Transport
      </div>
      <div className="flex justify-between items-center mb-6">
        <div className="text-xs text-slate-500 w-1/3">Handles connection & framing.</div>
        <div className="flex gap-2">
           <span className="flex items-center gap-1 px-2 py-1 bg-red-50 border border-red-200 rounded text-xs font-mono text-red-700 font-bold"><AlertTriangle size={12} /> Stdio</span>
           <span className="flex items-center gap-1 px-2 py-1 bg-emerald-50 border border-emerald-200 rounded text-xs font-mono text-emerald-700 font-bold"><Globe size={12} /> HTTP</span>
        </div>
      </div>
      <div className="bg-white border-2 border-purple-200 rounded-lg p-8 shadow-sm relative">
        <div className="absolute -top-3 left-6 bg-purple-100 px-3 py-1 rounded text-xs font-bold text-purple-700 uppercase tracking-wider">
          Inner Layer: Data Protocol
        </div>
        <div className="flex items-center gap-8 justify-center py-4">
          <div className="text-center">
            <div className="font-mono text-sm font-bold text-purple-900 bg-purple-50 px-3 py-2 rounded">JSON-RPC 2.0</div>
          </div>
          <ArrowRight className="text-purple-300" />
          <div className="flex gap-4">
             <div className="bg-purple-50 p-3 rounded border border-purple-100 text-center w-28">
               <Settings size={16} className="mx-auto text-purple-600 mb-1"/>
               <div className="text-[10px] font-bold text-purple-800">Lifecycle</div>
             </div>
             <div className="bg-purple-50 p-3 rounded border border-purple-100 text-center w-28">
               <MessageSquare size={16} className="mx-auto text-purple-600 mb-1"/>
               <div className="text-[10px] font-bold text-purple-800">Primitives</div>
             </div>
          </div>
        </div>
      </div>
    </div>
  </div>
);

const PrimitivesView = () => (
  <div className="min-w-[800px] w-full h-full p-8 flex flex-col gap-6">
     <div className="grid grid-cols-3 gap-6 h-full">
       {/* Tools (AI DRIVEN) */}
       <div className="bg-indigo-50 border-2 border-indigo-200 rounded-xl p-5 hover:shadow-md transition-all relative overflow-hidden">
         <div className="absolute top-0 right-0 p-2 opacity-10"><Sparkles size={60} /></div>
         <div className="flex items-center gap-2 text-indigo-800 font-bold mb-2">
           <Terminal size={20} /> Tools
         </div>
         <div className="text-[10px] uppercase font-bold text-indigo-600 mb-4 bg-indigo-100 inline-flex items-center gap-1 px-2 py-0.5 rounded border border-indigo-200">
           <Brain size={10} /> Model Controlled
         </div>
         <p className="text-xs text-indigo-900 mb-4 leading-relaxed">
           Functions the <strong className="text-indigo-700">AI chooses</strong> to call based on its reasoning.
         </p>
         <div className="bg-white p-3 rounded border border-indigo-200 font-mono text-[10px] text-slate-600 shadow-sm">
           <div>searchFlights(...)</div>
         </div>
       </div>

       {/* Resources (APP DRIVEN) */}
       <div className="bg-amber-50 border-2 border-amber-100 rounded-xl p-5 hover:shadow-md transition-all">
         <div className="flex items-center gap-2 text-amber-800 font-bold mb-2">
           <Database size={20} /> Resources
         </div>
         <div className="text-[10px] uppercase font-bold text-amber-600 mb-4 bg-amber-100 inline-block px-2 py-0.5 rounded">Application Controlled</div>
         <p className="text-xs text-amber-900 mb-4 leading-relaxed">
           Passive data sources loaded deterministically to fill context.
         </p>
         <div className="bg-white p-3 rounded border border-amber-200 font-mono text-[10px] text-slate-600 shadow-sm">
           <div>file:///logs/error.txt</div>
         </div>
       </div>

       {/* Prompts (USER DRIVEN) */}
       <div className="bg-blue-50 border-2 border-blue-100 rounded-xl p-5 hover:shadow-md transition-all">
         <div className="flex items-center gap-2 text-blue-800 font-bold mb-2">
           <MessageSquare size={20} /> Prompts
         </div>
         <div className="text-[10px] uppercase font-bold text-blue-600 mb-4 bg-blue-100 inline-block px-2 py-0.5 rounded">User Controlled</div>
         <p className="text-xs text-blue-900 mb-4 leading-relaxed">
           Templates explicitly selected by the human user.
         </p>
         <div className="bg-white p-3 rounded border border-blue-200 font-mono text-[10px] text-slate-600 shadow-sm">
           <div>"Plan a Vacation"</div>
         </div>
       </div>
     </div>
  </div>
);

// ==========================================
// 3. MODULE COMPONENTS
// ==========================================

const ArchitectureModule = () => {
  const [activeView, setActiveView] = useState('participants'); 
  const [selectedNode, setSelectedNode] = useState(null);

  return (
    <div className="flex flex-col h-full p-6 overflow-hidden">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-lg font-bold text-slate-700">Architecture Diagram</h2>
        <div className="flex bg-slate-200 p-1 rounded-lg">
          <button onClick={() => setActiveView('participants')} className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all ${activeView === 'participants' ? 'bg-white shadow text-blue-600' : 'text-slate-500'}`}>Participants</button>
          <button onClick={() => setActiveView('layers')} className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all ${activeView === 'layers' ? 'bg-white shadow text-purple-600' : 'text-slate-500'}`}>Layers</button>
          <button onClick={() => setActiveView('primitives')} className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all ${activeView === 'primitives' ? 'bg-white shadow text-emerald-600' : 'text-slate-500'}`}>Primitives</button>
        </div>
      </div>
      <div className="flex-grow bg-white rounded-xl border border-slate-200 shadow-sm relative overflow-auto">
        {activeView === 'participants' && <ParticipantsView selectedNode={selectedNode} setSelectedNode={setSelectedNode} />}
        {activeView === 'layers' && <LayersView />}
        {activeView === 'primitives' && <PrimitivesView />}
      </div>
    </div>
  );
};

const SecurityModule = () => {
  const [activeThreat, setActiveThreat] = useState(null);
  const [viewMode, setViewMode] = useState('diagram');
  const [showAiOnly, setShowAiOnly] = useState(false);

  const findT = (id) => THREATS.find(t => t.csa_ref === id) || THREATS[0];
  const visibleThreats = showAiOnly ? THREATS.filter(t => t.isAiNative) : THREATS;

  return (
    <div className="flex flex-col h-full p-6 overflow-hidden">
       {/* Security Header */}
       <div className="flex justify-between items-center mb-6">
          <h2 className="text-lg font-bold text-slate-700 flex items-center gap-2">
            Threat Landscape 
            {showAiOnly && <span className="text-xs bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded-full flex items-center gap-1 border border-indigo-200"><Sparkles size={10}/> AI Only</span>}
          </h2>
          <div className="flex gap-2">
             <button onClick={() => setShowAiOnly(!showAiOnly)} className={`flex items-center gap-2 px-3 py-1 rounded-md text-xs font-bold transition-all border ${showAiOnly ? 'bg-indigo-50 border-indigo-200 text-indigo-700' : 'bg-white border-slate-200 text-slate-500'}`}>
               <Sparkles size={12} /> {showAiOnly ? 'AI Filter On' : 'Filter AI'}
             </button>
             <div className="flex bg-slate-200 p-1 rounded-lg">
                <button onClick={() => setViewMode('diagram')} className={`px-3 py-1 rounded text-xs font-bold ${viewMode === 'diagram' ? 'bg-white text-blue-600 shadow' : 'text-slate-500'}`}>Map</button>
                <button onClick={() => setViewMode('list')} className={`px-3 py-1 rounded text-xs font-bold ${viewMode === 'list' ? 'bg-white text-purple-600 shadow' : 'text-slate-500'}`}>List</button>
             </div>
          </div>
       </div>

       {viewMode === 'list' && (
         <div className="grid grid-cols-2 gap-4 overflow-auto">
            {visibleThreats.map(t => (
               <div key={t.id} className={`p-3 bg-white border rounded-lg ${t.isAiNative ? 'border-indigo-200 shadow-sm' : 'border-slate-200'}`}>
                  <div className="flex justify-between items-start">
                     <div className="flex items-center gap-2 font-bold text-sm text-slate-700">
                        {t.icon} {t.title}
                     </div>
                     <span className="text-[10px] bg-slate-100 px-1.5 rounded text-slate-500">{t.csa_ref}</span>
                  </div>
                  <div className="text-xs text-slate-500 mt-2">{t.description}</div>
               </div>
            ))}
         </div>
       )}

       {viewMode === 'diagram' && (
         <div className="flex gap-6 h-full">
            {/* Diagram */}
            <div className="relative flex-grow bg-white rounded-xl shadow-sm border border-slate-200 p-8 overflow-auto min-h-[500px]">
               <div className="relative min-w-[1000px] min-h-[600px]">
                  {/* Host */}
                  <div className="absolute top-10 left-10 w-56 h-80 bg-blue-50 border-2 border-blue-200 rounded-lg p-4">
                     <div className="flex items-center gap-2 text-blue-900 font-bold mb-4"><Brain size={16}/> AI Host</div>
                     <div className="w-full h-48 bg-white border-2 border-dashed border-blue-300 rounded flex flex-col items-center justify-center relative">
                        <span className="text-xs font-bold text-blue-300">Client Runtime</span>
                        
                        {/* C03 UI Deception */}
                        <button onMouseEnter={() => setActiveThreat(findT('MCP-C03'))} className={`absolute top-2 right-2 p-1.5 bg-white rounded-full border border-yellow-400 shadow-sm hover:bg-yellow-50 ${!showAiOnly || findT('MCP-C03').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                           <Layout size={14} className="text-yellow-600"/>
                           {findT('MCP-C03').isAiNative && <span className="absolute -top-1 -right-1 flex h-2 w-2"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-yellow-400 opacity-75"></span><span className="relative inline-flex rounded-full h-2 w-2 bg-yellow-500"></span></span>}
                        </button>
                        
                        {/* C07 Malicious Output */}
                         <button onMouseEnter={() => setActiveThreat(findT('MCP-C07'))} className={`absolute bottom-2 right-2 p-1.5 bg-white rounded-full border border-red-400 shadow-sm hover:bg-red-50 ${!showAiOnly || findT('MCP-C07').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                           <Code size={14} className="text-red-600"/>
                            {findT('MCP-C07').isAiNative && <span className="absolute -top-1 -right-1 flex h-2 w-2"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span><span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span></span>}
                        </button>

                        {/* C06 Unconstrained Approval */}
                        <button onMouseEnter={() => setActiveThreat(findT('MCP-C06'))} className={`absolute bottom-2 left-2 p-1.5 bg-white rounded-full border border-purple-400 shadow-sm hover:bg-purple-50 ${!showAiOnly || findT('MCP-C06').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                           <User size={14} className="text-purple-600"/>
                            {findT('MCP-C06').isAiNative && <span className="absolute -top-1 -right-1 flex h-2 w-2"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-purple-400 opacity-75"></span><span className="relative inline-flex rounded-full h-2 w-2 bg-purple-500"></span></span>}
                        </button>
                     </div>

                     {/* C02 Insecure Storage */}
                     <button onMouseEnter={() => setActiveThreat(findT('MCP-C02'))} className={`absolute bottom-2 right-2 p-1.5 bg-white rounded-full border border-orange-400 shadow-sm hover:bg-orange-50 ${!showAiOnly || findT('MCP-C02').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                        <Lock size={14} className="text-orange-600"/>
                     </button>
                  </div>

                  {/* Server */}
                  <div className="absolute top-10 left-[400px] w-64 h-[420px] bg-slate-50 border-2 border-slate-300 rounded-lg p-4">
                     <div className="flex items-center gap-2 text-slate-700 font-bold mb-4"><Server size={16}/> MCP Server</div>
                     
                     {/* Layer 1: Definition */}
                     <div className="bg-white p-2 rounded border border-slate-200 mb-2 relative">
                        <span className="text-[10px] text-slate-400 font-bold">Layer 1: Defs</span>
                        {/* S03 Poisoning */}
                        <button onMouseEnter={() => setActiveThreat(findT('MCP-S03'))} className={`absolute top-2 right-2 p-1 bg-white rounded-full border border-red-200 hover:bg-red-50 ${!showAiOnly || findT('MCP-S03').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                           <FileWarning size={14} className="text-red-500"/>
                           {findT('MCP-S03').isAiNative && <span className="absolute -top-1 -right-1 flex h-2 w-2"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span><span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span></span>}
                        </button>
                        {/* S05 Insecure Config */}
                        <button onMouseEnter={() => setActiveThreat(findT('MCP-S05'))} className={`absolute top-2 right-8 p-1 bg-white rounded-full border border-gray-200 hover:bg-gray-50 ${!showAiOnly || findT('MCP-S05').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                           <Server size={14} className="text-gray-500"/>
                        </button>
                     </div>

                     {/* Layer 2: Logic */}
                     <div className="bg-slate-800 p-2 rounded border border-slate-600 relative h-32 mb-2">
                        <span className="text-[10px] text-slate-400 font-bold">Layer 2: Logic</span>
                         {/* S01 Prompt Injection */}
                         <button onMouseEnter={() => setActiveThreat(findT('MCP-S01'))} className={`absolute top-8 right-2 p-1.5 bg-slate-700 rounded-full border border-red-500 hover:bg-red-900 ${!showAiOnly || findT('MCP-S01').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                           <Terminal size={14} className="text-red-400"/>
                           {findT('MCP-S01').isAiNative && <span className="absolute -top-1 -right-1 flex h-2 w-2"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span><span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span></span>}
                        </button>
                        
                        {/* S07 Excessive Agency */}
                         <button onMouseEnter={() => setActiveThreat(findT('MCP-S07'))} className={`absolute bottom-2 left-2 p-1.5 bg-slate-700 rounded-full border border-blue-500 hover:bg-blue-900 ${!showAiOnly || findT('MCP-S07').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                           <Shield size={14} className="text-blue-400"/>
                           {findT('MCP-S07').isAiNative && <span className="absolute -top-1 -right-1 flex h-2 w-2"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span><span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500"></span></span>}
                        </button>

                        {/* S02 Confused Deputy */}
                        <button onMouseEnter={() => setActiveThreat(findT('MCP-S02'))} className={`absolute bottom-2 right-2 p-1.5 bg-slate-700 rounded-full border border-orange-500 hover:bg-orange-900 ${!showAiOnly || findT('MCP-S02').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                           <User size={14} className="text-orange-400"/>
                           {findT('MCP-S02').isAiNative && <span className="absolute -top-1 -right-1 flex h-2 w-2"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-orange-400 opacity-75"></span><span className="relative inline-flex rounded-full h-2 w-2 bg-orange-500"></span></span>}
                        </button>
                     </div>

                     {/* Layer 3: Data */}
                     <div className="bg-yellow-50 p-2 rounded border border-yellow-200 mb-2 relative">
                        <span className="text-[10px] text-yellow-800 font-bold">Layer 3: Data</span>
                        {/* S04 Credential Exposure */}
                        <button onMouseEnter={() => setActiveThreat(findT('MCP-S04'))} className={`absolute top-1 right-2 p-1 bg-white rounded-full border border-yellow-300 hover:bg-yellow-100 ${!showAiOnly || findT('MCP-S04').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                           <Lock size={12} className="text-yellow-600"/>
                        </button>
                     </div>

                     {/* Layer 4: Supply Chain */}
                     <div className="bg-pink-50 p-2 rounded border border-pink-200 relative">
                        <span className="text-[10px] text-pink-800 font-bold">Layer 4: Deps</span>
                        {/* S06 Supply Chain */}
                        <button onMouseEnter={() => setActiveThreat(findT('MCP-S06'))} className={`absolute top-1 right-2 p-1 bg-white rounded-full border border-pink-300 hover:bg-pink-100 ${!showAiOnly || findT('MCP-S06').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                           <Database size={12} className="text-pink-600"/>
                        </button>
                     </div>

                     {/* S08 Data Exfiltration */}
                     <button onMouseEnter={() => setActiveThreat(findT('MCP-S08'))} className={`absolute top-1/2 -right-3 p-1.5 bg-white rounded-full border border-purple-400 shadow hover:bg-purple-50 ${!showAiOnly || findT('MCP-S08').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                        <Activity size={14} className="text-purple-600"/>
                     </button>
                  </div>
                  
                  {/* Connection */}
                  <div className="absolute top-32 left-[240px] w-40 h-2 bg-slate-300"></div>
                  
                  {/* C01 Malicious Connection */}
                  <button onMouseEnter={() => setActiveThreat(findT('MCP-C01'))} className={`absolute top-[115px] left-[260px] p-1.5 bg-white rounded-full border border-red-200 hover:bg-red-50 z-20 ${!showAiOnly ? 'opacity-100' : 'opacity-20'}`}>
                      <Network size={14} className="text-red-600"/>
                   </button>

                  {/* S10 Transport */}
                   <button onMouseEnter={() => setActiveThreat(findT('MCP-S10'))} className={`absolute top-[115px] left-[320px] p-1.5 bg-white rounded-full border border-teal-200 hover:bg-teal-50 z-20 ${!showAiOnly ? 'opacity-100' : 'opacity-20'}`}>
                      <Globe size={14} className="text-teal-600"/>
                   </button>

                   {/* External Context */}
                   <div className="absolute top-48 left-[700px] w-40 h-24 bg-indigo-50 border-2 border-indigo-100 rounded-lg p-3 flex flex-col justify-center items-center shadow-sm">
                      <div className="text-indigo-900 font-bold text-xs mb-1">External Context</div>
                      {/* S09 Context Spoofing */}
                      <button onMouseEnter={() => setActiveThreat(findT('MCP-S09'))} className={`absolute -left-3 top-8 p-1.5 bg-white rounded-full border border-indigo-300 shadow hover:bg-indigo-50 ${!showAiOnly || findT('MCP-S09').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                         <Eye size={14} className="text-indigo-600"/>
                         {findT('MCP-S09').isAiNative && <span className="absolute -top-1 -right-1 flex h-2 w-2"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75"></span><span className="relative inline-flex rounded-full h-2 w-2 bg-indigo-500"></span></span>}
                      </button>
                   </div>
                   
                   {/* Context Line */}
                   <div className="absolute top-60 left-[670px] w-[30px] h-2 bg-slate-200 border-t border-b border-slate-300 dashed"></div>
               </div>
            </div>

            {/* Details Panel */}
            <div className="w-80 bg-white border-l border-slate-200 p-4 overflow-y-auto">
               <h3 className="font-bold text-slate-800 border-b pb-2 mb-4">Details</h3>
               {activeThreat ? (
                 <div className="animate-in fade-in slide-in-from-right-2 duration-200">
                    <div className="flex items-center gap-2 mb-2">
                       {activeThreat.icon}
                       <span className="font-bold text-sm text-slate-800">{activeThreat.title}</span>
                    </div>
                    {activeThreat.isAiNative && <div className="inline-block bg-indigo-100 text-indigo-800 text-[10px] px-2 py-0.5 rounded-full font-bold mb-4">AI-Native Threat</div>}
                    <div className="text-xs text-slate-600 mb-4">{activeThreat.description}</div>
                    
                    <div className="space-y-3">
                      <div className="bg-slate-50 p-2 rounded border border-slate-200">
                         <div className="text-[10px] font-bold text-slate-400 uppercase flex items-center gap-1">
                           <ScanLine size={10} /> AST / Static Rule
                         </div>
                         <div className="text-xs font-mono text-slate-700 mt-1">{activeThreat.ast_rule}</div>
                      </div>

                      <div className="bg-indigo-50 p-2 rounded border border-indigo-100">
                         <div className="text-[10px] font-bold text-indigo-400 uppercase flex items-center gap-1">
                           <Brain size={10} /> Semantic / LLM Rule
                         </div>
                         <div className="text-xs font-mono text-indigo-800 mt-1">{activeThreat.llm_rule}</div>
                      </div>
                    </div>
                 </div>
               ) : (
                 <div className="text-center text-slate-400 mt-10 text-xs">Hover over the diagram to see detection rules.</div>
               )}
            </div>
         </div>
       )}
    </div>
  );
};

// ==========================================
// 4. MAIN COMPONENT (Defined LAST to satisfy dependencies)
// ==========================================

const MCPUnifiedView = () => {
  const [currentModule, setCurrentModule] = useState('architecture'); // 'architecture' | 'security'

  return (
    <div className="flex flex-col h-full bg-slate-50 text-slate-800 font-sans overflow-hidden">
      {/* Top Level Navigation Bar */}
      <div className="bg-white border-b border-slate-200 px-6 py-4 flex justify-between items-center shadow-sm z-10">
        <div>
          <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <div className="bg-blue-600 text-white p-1 rounded">M</div>
            Model Context Protocol
          </h1>
        </div>
        
        <div className="flex bg-slate-100 p-1 rounded-lg border border-slate-200">
          <button
            onClick={() => setCurrentModule('architecture')}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
              currentModule === 'architecture' 
                ? 'bg-white shadow text-blue-600 ring-1 ring-slate-200' 
                : 'text-slate-500 hover:text-slate-900'
            }`}
          >
            <Layers size={16} /> Core Architecture
          </button>
          <button
            onClick={() => setCurrentModule('security')}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
              currentModule === 'security' 
                ? 'bg-white shadow text-indigo-600 ring-1 ring-slate-200' 
                : 'text-slate-500 hover:text-slate-900'
            }`}
          >
            <Shield size={16} /> Security & Threats
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-grow overflow-hidden relative">
        {currentModule === 'architecture' ? <ArchitectureModule /> : <SecurityModule />}
      </div>
    </div>
  );
};

export default MCPUnifiedView;
