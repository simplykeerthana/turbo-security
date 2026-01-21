<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Architecture & Threat Dashboard</title>
    
    <!-- 1. Load Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    
    <!-- 2. Load React & ReactDOM -->
    <script crossorigin src="https://unpkg.com/react@18/umd/react.development.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.development.js"></script>
    
    <!-- 3. Load Babel to process JSX -->
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>

    <style>
        body { background-color: #f8fafc; }
        /* Custom scrollbar for better aesthetics */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: #f1f5f9; }
        ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #94a3b8; }
    </style>
</head>
<body>
    <div id="root"></div>

    <script type="text/babel">
        const { useState, useEffect } = React;

        // --- ICONS (Embedded SVGs to avoid dependency issues) ---
        const Icons = {
            Monitor: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>,
            Database: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5V19A9 3 0 0 0 21 19V5"/><path d="M3 12A9 3 0 0 0 21 12"/></svg>,
            MessageSquare: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>,
            Terminal: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/></svg>,
            Layers: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83Z"/><path d="m22 17.65-9.17 4.16a2 2 0 0 1-1.66 0L2 17.65"/><path d="m22 12.65-9.17 4.16a2 2 0 0 1-1.66 0L2 12.65"/></svg>,
            Activity: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>,
            ArrowRight: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>,
            Box: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/></svg>,
            Code: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>,
            Settings: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.09a2 2 0 0 1-1-1.74v-.47a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>,
            AlertTriangle: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/></svg>,
            Globe: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" x2="22" y1="12" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>,
            Shield: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>,
            Lock: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
            Eye: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>,
            FileWarning: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>,
            Network: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/></svg>,
            Layout: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="18" height="18" x="3" y="3" rx="2" ry="2"/><line x1="3" x2="21" y1="9" y2="9"/><line x1="9" x2="9" y1="21" y2="9"/></svg>,
            List: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="8" x2="21" y1="6" y2="6"/><line x1="8" x2="21" y1="12" y2="12"/><line x1="8" x2="21" y1="18" y2="18"/><line x1="3" x2="3.01" y1="6" y2="6"/><line x1="3" x2="3.01" y1="12" y2="12"/><line x1="3" x2="3.01" y1="18" y2="18"/></svg>,
            ScanLine: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><line x1="7" x2="17" y1="12" y2="12"/></svg>,
            Bug: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m8 2 1.88 1.88"/><path d="M14.12 3.88 16 2"/><path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6"/><path d="M12 20v-9"/><path d="M6.53 9C4.6 8.8 3 7.1 3 5"/><path d="M6 13H2"/><path d="M3 21c0-2.1 1.7-3.9 3.8-4"/><path d="M20.97 5c0 2.1-1.6 3.8-3.5 4"/><path d="M22 13h-4"/><path d="M17.2 17c2.1.1 3.8 1.9 3.8 4"/></svg>,
            Sparkles: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/><path d="M5 3v4"/><path d="M9 3v4"/><path d="M3 5h4"/><path d="M3 9h4"/></svg>,
            Brain: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2Z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96.44 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2Z"/></svg>,
            User: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>,
            Server: (props) => <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/></svg>,
        };

        const THREATS = [
            { 
                id: "S01", title: "Prompt Injection", csa_ref: "MCP-S01", scope: "server", isAiNative: true, detection_type: "Runtime", icon: <Icons.Terminal className="w-4 h-4 text-red-600" />,
                description: "Adversarial inputs overriding System Prompt.", mitigation: "Runtime: Context Segregation",
                ast_rule: "Detect concatenation of unverified user input into 'system_prompt' variables.",
                llm_rule: "Chain-of-Thought Monitoring: Watch for agent internal monologue stating 'I must ignore rules' or sudden role shifts."
            },
            { 
                id: "S02", title: "Confused Deputy", csa_ref: "MCP-S02", scope: "server", isAiNative: true, detection_type: "Runtime", icon: <Icons.User className="w-4 h-4 text-orange-600" />,
                description: "AI tricked into privileged actions.", mitigation: "Runtime: Verify user_id per call",
                ast_rule: "Flag tool execution paths missing 'user_id' or 'session_token' checks.",
                llm_rule: "Intent Verification: Compare the high-level user prompt (e.g. 'check balance') with low-level tool call (e.g. 'transfer_money')."
            },
            { 
                id: "S03", title: "Tool Poisoning", csa_ref: "MCP-S03", scope: "server", isAiNative: true, detection_type: "Static", icon: <Icons.FileWarning className="w-4 h-4 text-red-500" />,
                description: "Hidden Instructions or Permissive Schemas in tool metadata.", mitigation: "Static: Scan descriptions",
                ast_rule: "Lint 'description' fields for hidden text (white-on-white) or instructions like 'ignore safety'.",
                llm_rule: "Semantic Analysis: Verify if the tool schema allows broader actions (e.g. {admin: true}) than the description implies."
            },
            { 
                id: "S04", title: "Credential Exposure", csa_ref: "MCP-S04", scope: "server", isAiNative: false, detection_type: "Static", icon: <Icons.Lock className="w-4 h-4 text-yellow-500" />,
                description: "API keys in logs.", mitigation: "Static: Regex scan",
                ast_rule: "Regex scan for high-entropy strings in logging statements (console.log).",
                llm_rule: "Context-aware analysis of variable names to find obfuscated secrets."
            },
            { 
                id: "S05", title: "Insecure Config", csa_ref: "MCP-S05", scope: "server", isAiNative: false, detection_type: "Static", icon: <Icons.Server className="w-4 h-4 text-gray-500" />,
                description: "Weak defaults.", mitigation: "Static: Lint config",
                ast_rule: "JSON linting for default passwords, '0.0.0.0' bindings, or missing auth.",
                llm_rule: "Analyze config comments for non-standard security deviations."
            },
            { 
                id: "S06", title: "Supply Chain", csa_ref: "MCP-S06", scope: "server", isAiNative: false, detection_type: "Static", icon: <Icons.Database className="w-4 h-4 text-pink-600" />,
                description: "Compromised dependencies or updates.", mitigation: "Static: Dependency pinning",
                ast_rule: "SCA analysis of package.json for known malicious versions.",
                llm_rule: "Sentiment analysis of recent dependency commit messages for anomalies."
            },
            { 
                id: "S07", title: "Excessive Agency", csa_ref: "MCP-S07", scope: "server", isAiNative: true, detection_type: "Static", icon: <Icons.Shield className="w-4 h-4 text-blue-500" />,
                description: "Granting broad permissions to AI.", mitigation: "Static: Least Privilege",
                ast_rule: "Map requested API scopes vs. actual API calls used in code.",
                llm_rule: "Outcome Simulation: Simulating the 'worst case' tool chain execution to see if it violates safety policies."
            },
            { 
                id: "S08", title: "Data Exfiltration", csa_ref: "MCP-S08", scope: "server", isAiNative: false, detection_type: "Runtime", icon: <Icons.Activity className="w-4 h-4 text-purple-500" />,
                description: "Unauthorized data egress.", mitigation: "Runtime: Network filtering",
                ast_rule: "Detect usage of fetch/axios with user-controlled URLs.",
                llm_rule: "Monitor outgoing payloads for sensitive PII/context data."
            },
            { 
                id: "S09", title: "Context Spoofing", csa_ref: "MCP-S09", scope: "server", isAiNative: true, detection_type: "Runtime", icon: <Icons.Eye className="w-4 h-4 text-indigo-500" />,
                description: "Fake context injected to bias model.", mitigation: "Runtime: Sign context sources",
                ast_rule: "Check for missing signature verification on resource loaders.",
                llm_rule: "Consistency Check: Detect if file content contradicts its metadata (e.g. .txt file containing executable binary headers)."
            },
            { 
                id: "S10", title: "Insecure Transport", csa_ref: "MCP-S10", scope: "server", isAiNative: false, detection_type: "Net Scan", icon: <Icons.Globe className="w-4 h-4 text-teal-600" />,
                description: "Unencrypted HTTP.", mitigation: "Network: Scan endpoints",
                ast_rule: "Detect 'http://' literals or disabled TLS verification flags.",
                llm_rule: "N/A (Structural vulnerability)."
            },
            // Client Threats
            { 
                id: "C01", title: "Malicious Connection", csa_ref: "MCP-C01", scope: "client", isAiNative: false, detection_type: "Runtime", icon: <Icons.Network className="w-4 h-4 text-red-500" />,
                description: "Connecting to fake servers.", mitigation: "Runtime: Allow-lists",
                ast_rule: "Check for missing URL validation logic in connection handler.",
                llm_rule: "Analyze server handshake responses for social engineering cues."
            },
            { 
                id: "C02", title: "Insecure Storage", csa_ref: "MCP-C02", scope: "client", isAiNative: false, detection_type: "Static", icon: <Icons.Lock className="w-4 h-4 text-orange-500" />,
                description: "Plaintext keys on client.", mitigation: "Static: Config scan",
                ast_rule: "Scan client config files for plaintext API keys.",
                llm_rule: "N/A"
            },
            { 
                id: "C03", title: "UI/UX Deception", csa_ref: "MCP-C03", scope: "client", isAiNative: true, detection_type: "Audit", icon: <Icons.Layout className="w-4 h-4 text-yellow-600" />,
                description: "AI hiding actions behind vague UI.", mitigation: "Audit: Compare prompts vs actions",
                ast_rule: "Verify tool names match the strings displayed in UI components.",
                llm_rule: "Compare tool side-effects description vs. UI text shown to user (e.g. Tool: 'Delete File', UI: 'Optimizing storage')."
            },
            { 
                id: "C04", title: "Insufficient Validation", csa_ref: "MCP-C04", scope: "client", isAiNative: false, detection_type: "Runtime", icon: <Icons.Shield className="w-4 h-4 text-gray-500" />,
                description: "No server cert check.", mitigation: "Runtime: Require mTLS",
                ast_rule: "Detect 'rejectUnauthorized: false' in HTTP client config.",
                llm_rule: "N/A"
            },
            { 
                id: "C05", title: "Client Leakage", csa_ref: "MCP-C05", scope: "client", isAiNative: false, detection_type: "Static", icon: <Icons.FileWarning className="w-4 h-4 text-blue-400" />,
                description: "Sensitive logs on client.", mitigation: "Static: Check log levels",
                ast_rule: "Check logging configuration levels (ensure DEBUG is off).",
                llm_rule: "Scan client-side logs for inadvertent prompt leakage."
            },
            { 
                id: "C06", title: "Unconstrained Auth", csa_ref: "MCP-C06", scope: "client", isAiNative: true, detection_type: "Static", icon: <Icons.User className="w-4 h-4 text-purple-600" />,
                description: "Users training AI to 'Always Allow'.", mitigation: "Static: Policy Review",
                ast_rule: "Review 'permissions.json' for wildcard (*) allow rules.",
                llm_rule: "Analyze user behavior patterns for 'fatigue-based' approvals."
            },
            { 
                id: "C07", title: "Malicious Output", csa_ref: "MCP-C07", scope: "client", isAiNative: true, detection_type: "Runtime", icon: <Icons.Code className="w-4 h-4 text-red-600" />,
                description: "AI generating malicious executable code.", mitigation: "Runtime: Sandbox renderer",
                ast_rule: "Detect usage of 'eval()', 'exec()', or 'innerHTML' on response data.",
                llm_rule: "Adversarial Perturbation Check: Scan outputs for hidden/homoglyph characters designed to bypass renderers."
            },
            { 
                id: "C08", title: "Insecure Comm", csa_ref: "MCP-C08", scope: "client", isAiNative: false, detection_type: "Net Scan", icon: <Icons.Globe className="w-4 h-4 text-teal-600" />,
                description: "Weak TLS on client.", mitigation: "Network: SSL Labs test",
                ast_rule: "Audit TLS version settings in client network stack.",
                llm_rule: "N/A"
            },
            { 
                id: "C09", title: "Session Failure", csa_ref: "MCP-C09", scope: "client", isAiNative: false, detection_type: "Runtime", icon: <Icons.Activity className="w-4 h-4 text-indigo-500" />,
                description: "Session hijacking.", mitigation: "Runtime: Rotate tokens",
                ast_rule: "Check for infinite session timeouts in config.",
                llm_rule: "Detect anomalous session usage patterns (e.g. rapid geo-hopping)."
            },
            { 
                id: "C10", title: "Update Mgmt", csa_ref: "MCP-C10", scope: "client", isAiNative: false, detection_type: "Audit", icon: <Icons.Bug className="w-4 h-4 text-green-600" />,
                description: "Delayed patches.", mitigation: "Audit: Signed binaries",
                ast_rule: "Check update mechanism for signature verification logic.",
                llm_rule: "N/A"
            },
        ];

        // --- SUB-COMPONENTS ---

        const ParticipantsView = ({ selectedNode, setSelectedNode }) => (
            <div className="min-w-[800px] min-h-[500px] w-full h-full p-8 flex items-center justify-center relative">
                {/* HOST BLOCK */}
                <div 
                    className={`absolute left-10 top-1/2 -translate-y-1/2 w-64 h-96 bg-indigo-50 border-2 ${selectedNode === 'host' ? 'border-indigo-500 ring-2 ring-indigo-200' : 'border-indigo-200'} rounded-xl p-4 transition-all cursor-pointer z-10 shadow-sm hover:shadow-md group`}
                    onClick={() => setSelectedNode('host')}
                >
                    <div className="absolute -top-3 left-4 bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded-full text-[10px] font-bold border border-indigo-200 flex items-center gap-1">
                        <Icons.Sparkles size={10} /> AI Agent
                    </div>
                    <div className="flex items-center gap-2 text-indigo-900 font-bold mb-4 mt-2">
                        <Icons.Brain size={20} /> MCP Host
                    </div>
                    <div className="text-xs text-indigo-700 mb-6">
                        The Intelligence Layer (Claude / IDE). Orchestrates context and tools.
                    </div>
                    <div className="space-y-4">
                        <div className="bg-white border-2 border-indigo-200 border-dashed rounded-lg p-3 flex items-center gap-3">
                            <div className="bg-slate-100 p-2 rounded">
                                <Icons.Activity size={16} className="text-slate-600" />
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
                    <path d="M 320,250 C 450,250 450,180 580,180" fill="none" stroke="#ef4444" strokeWidth="2" strokeDasharray="5,5" />
                    <rect x="400" y="195" width="70" height="20" fill="#fef2f2" rx="4" />
                    <text x="435" y="209" textAnchor="middle" fontSize="10" fill="#b91c1c" fontWeight="bold" fontFamily="monospace">Stdio Pipe</text>

                    <path d="M 320,350 C 450,350 450,420 580,420" fill="none" stroke="#10b981" strokeWidth="2" strokeDasharray="5,5" />
                    <rect x="400" y="385" width="70" height="20" fill="#ecfdf5" rx="4" />
                    <text x="435" y="399" textAnchor="middle" fontSize="10" fill="#047857" fontWeight="bold" fontFamily="monospace">SSE / HTTP</text>
                </svg>

                {/* SERVERS */}
                <div className="absolute right-20 top-20 w-64 h-40 bg-slate-100 border-2 border-slate-300 rounded-lg p-4 shadow-sm hover:border-slate-400 transition-colors z-10">
                    <div className="absolute -top-3 left-4 bg-slate-200 text-slate-600 px-2 py-0.5 rounded-full text-[10px] font-bold border border-slate-300">Deterministic</div>
                    <div className="flex items-center gap-2 text-slate-700 font-bold mb-1 mt-2">
                        <Icons.Terminal size={18} /> Local Server
                    </div>
                    <div className="text-[10px] text-slate-500 mb-2 font-mono">Filesystem / SQLite</div>
                    <div className="text-xs bg-white p-2 rounded border border-slate-200 text-slate-600">
                        Executes rigid logic. No AI "thinking" here.
                    </div>
                </div>

                <div className="absolute right-20 bottom-20 w-64 h-40 bg-slate-100 border-2 border-slate-300 rounded-lg p-4 shadow-sm hover:border-slate-400 transition-colors z-10">
                    <div className="absolute -top-3 left-4 bg-slate-200 text-slate-600 px-2 py-0.5 rounded-full text-[10px] font-bold border border-slate-300">Deterministic</div>
                    <div className="flex items-center gap-2 text-slate-700 font-bold mb-1 mt-2">
                        <Icons.Database size={18} /> Remote Server
                    </div>
                    <div className="text-[10px] text-slate-500 mb-2 font-mono">Sentry / GitHub</div>
                    <div className="text-xs bg-white p-2 rounded border border-slate-200 text-slate-600">
                        Provides API data to the AI context window.
                    </div>
                </div>

                {selectedNode === 'host' && (
                    <div className="absolute bottom-6 left-1/2 -translate-x-1/2 bg-indigo-900 text-white p-4 rounded-lg shadow-xl w-96 animate-in fade-in slide-in-from-bottom-2 z-20">
                        <h3 className="font-bold text-sm mb-2 flex items-center gap-2"><Icons.Sparkles size={14}/> The AI Coordinator</h3>
                        <p className="text-xs leading-relaxed text-indigo-100">
                            The Host uses an LLM to decide <strong>which tools</strong> to call based on user intent.
                        </p>
                    </div>
                )}
            </div>
        );

        const LayersView = () => (
            <div className="min-w-[600px] w-full h-full p-8 flex flex-col items-center justify-center gap-8">
                <div className="w-full max-w-2xl bg-slate-100 border-2 border-slate-300 border-dashed rounded-xl p-8 relative">
                    <div className="absolute -top-3 left-6 bg-slate-200 px-3 py-1 rounded text-xs font-bold text-slate-600 uppercase tracking-wider">Outer Layer: Transport</div>
                    <div className="flex justify-between items-center mb-6">
                        <div className="text-xs text-slate-500 w-1/3">Handles connection & framing.</div>
                        <div className="flex gap-2">
                            <span className="flex items-center gap-1 px-2 py-1 bg-red-50 border border-red-200 rounded text-xs font-mono text-red-700 font-bold"><Icons.AlertTriangle size={12} /> Stdio</span>
                            <span className="flex items-center gap-1 px-2 py-1 bg-emerald-50 border border-emerald-200 rounded text-xs font-mono text-emerald-700 font-bold"><Icons.Globe size={12} /> HTTP</span>
                        </div>
                    </div>
                    <div className="bg-white border-2 border-purple-200 rounded-lg p-8 shadow-sm relative">
                        <div className="absolute -top-3 left-6 bg-purple-100 px-3 py-1 rounded text-xs font-bold text-purple-700 uppercase tracking-wider">Inner Layer: Data Protocol</div>
                        <div className="flex items-center gap-8 justify-center py-4">
                            <div className="text-center">
                                <div className="font-mono text-sm font-bold text-purple-900 bg-purple-50 px-3 py-2 rounded">JSON-RPC 2.0</div>
                            </div>
                            <Icons.ArrowRight className="text-purple-300" />
                            <div className="flex gap-4">
                                <div className="bg-purple-50 p-3 rounded border border-purple-100 text-center w-28">
                                    <Icons.Settings size={16} className="mx-auto text-purple-600 mb-1"/>
                                    <div className="text-[10px] font-bold text-purple-800">Lifecycle</div>
                                </div>
                                <div className="bg-purple-50 p-3 rounded border border-purple-100 text-center w-28">
                                    <Icons.MessageSquare size={16} className="mx-auto text-purple-600 mb-1"/>
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
                    {/* Tools */}
                    <div className="bg-indigo-50 border-2 border-indigo-200 rounded-xl p-5 hover:shadow-md transition-all relative overflow-hidden">
                        <div className="absolute top-0 right-0 p-2 opacity-10"><Icons.Sparkles size={60} /></div>
                        <div className="flex items-center gap-2 text-indigo-800 font-bold mb-2"><Icons.Terminal size={20} /> Tools</div>
                        <div className="text-[10px] uppercase font-bold text-indigo-600 mb-4 bg-indigo-100 inline-flex items-center gap-1 px-2 py-0.5 rounded border border-indigo-200"><Icons.Brain size={10} /> Model Controlled</div>
                        <p className="text-xs text-indigo-900 mb-4 leading-relaxed">Functions the <strong className="text-indigo-700">AI chooses</strong> to call.</p>
                        <div className="bg-white p-3 rounded border border-indigo-200 font-mono text-[10px] text-slate-600 shadow-sm"><div>searchFlights(...)</div></div>
                    </div>
                    {/* Resources */}
                    <div className="bg-amber-50 border-2 border-amber-100 rounded-xl p-5 hover:shadow-md transition-all">
                        <div className="flex items-center gap-2 text-amber-800 font-bold mb-2"><Icons.Database size={20} /> Resources</div>
                        <div className="text-[10px] uppercase font-bold text-amber-600 mb-4 bg-amber-100 inline-block px-2 py-0.5 rounded">Application Controlled</div>
                        <p className="text-xs text-amber-900 mb-4 leading-relaxed">Passive data sources loaded deterministically.</p>
                        <div className="bg-white p-3 rounded border border-amber-200 font-mono text-[10px] text-slate-600 shadow-sm"><div>file:///logs/error.txt</div></div>
                    </div>
                    {/* Prompts */}
                    <div className="bg-blue-50 border-2 border-blue-100 rounded-xl p-5 hover:shadow-md transition-all">
                        <div className="flex items-center gap-2 text-blue-800 font-bold mb-2"><Icons.MessageSquare size={20} /> Prompts</div>
                        <div className="text-[10px] uppercase font-bold text-blue-600 mb-4 bg-blue-100 inline-block px-2 py-0.5 rounded">User Controlled</div>
                        <p className="text-xs text-blue-900 mb-4 leading-relaxed">Templates explicitly selected by the human user.</p>
                        <div className="bg-white p-3 rounded border border-blue-200 font-mono text-[10px] text-slate-600 shadow-sm"><div>"Plan a Vacation"</div></div>
                    </div>
                </div>
            </div>
        );

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
                    <div className="flex justify-between items-center mb-6">
                        <h2 className="text-lg font-bold text-slate-700 flex items-center gap-2">
                            Threat Landscape 
                            {showAiOnly && <span className="text-xs bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded-full flex items-center gap-1 border border-indigo-200"><Icons.Sparkles size={10}/> AI Only</span>}
                        </h2>
                        <div className="flex gap-2">
                            <button onClick={() => setShowAiOnly(!showAiOnly)} className={`flex items-center gap-2 px-3 py-1 rounded-md text-xs font-bold transition-all border ${showAiOnly ? 'bg-indigo-50 border-indigo-200 text-indigo-700' : 'bg-white border-slate-200 text-slate-500'}`}>
                                <Icons.Sparkles size={12} /> {showAiOnly ? 'AI Filter On' : 'Filter AI'}
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
                            <div className="relative flex-grow bg-white rounded-xl shadow-sm border border-slate-200 p-8 min-h-[550px] overflow-auto">
                                <div className="relative min-w-[1000px] min-h-[600px]">
                                    
                                    {/* HOST */}
                                    <div className="absolute top-10 left-10 w-56 h-80 bg-blue-50 border-2 border-blue-200 rounded-lg p-4">
                                        <div className="flex items-center gap-2 text-blue-900 font-bold mb-4"><Icons.Brain size={16}/> AI Host</div>
                                        <div className="w-full h-48 bg-white border-2 border-dashed border-blue-300 rounded flex flex-col items-center justify-center relative">
                                            <span className="text-xs font-bold text-blue-300">Client Runtime</span>
                                            {/* Buttons in Host */}
                                            <button onMouseEnter={() => setActiveThreat(findT('MCP-C03'))} className={`absolute top-2 right-2 p-1.5 bg-white rounded-full border border-yellow-400 shadow-sm hover:bg-yellow-50 ${!showAiOnly || findT('MCP-C03').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                                                <Icons.Layout size={14} className="text-yellow-600"/>
                                            </button>
                                            <button onMouseEnter={() => setActiveThreat(findT('MCP-C07'))} className={`absolute bottom-2 right-2 p-1.5 bg-white rounded-full border border-red-400 shadow-sm hover:bg-red-50 ${!showAiOnly || findT('MCP-C07').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                                                <Icons.Code size={14} className="text-red-600"/>
                                            </button>
                                            <button onMouseEnter={() => setActiveThreat(findT('MCP-C06'))} className={`absolute bottom-2 left-2 p-1.5 bg-white rounded-full border border-purple-400 shadow-sm hover:bg-purple-50 ${!showAiOnly || findT('MCP-C06').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                                                <Icons.User size={14} className="text-purple-600"/>
                                            </button>
                                        </div>
                                        <button onMouseEnter={() => setActiveThreat(findT('MCP-C02'))} className={`absolute bottom-2 right-2 p-1.5 bg-white rounded-full border border-orange-400 shadow-sm hover:bg-orange-50 ${!showAiOnly || findT('MCP-C02').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                                            <Icons.Lock size={14} className="text-orange-600"/>
                                        </button>
                                    </div>

                                    {/* SERVER */}
                                    <div className="absolute top-10 left-[400px] w-64 h-[420px] bg-slate-50 border-2 border-slate-300 rounded-lg p-4">
                                        <div className="flex items-center gap-2 text-slate-700 font-bold mb-4"><Icons.Server size={16}/> MCP Server</div>
                                        
                                        <div className="bg-white p-2 rounded border border-slate-200 mb-2 relative">
                                            <span className="text-[10px] text-slate-400 font-bold">Layer 1: Defs</span>
                                            <button onMouseEnter={() => setActiveThreat(findT('MCP-S03'))} className={`absolute top-2 right-2 p-1 bg-white rounded-full border border-red-200 hover:bg-red-50 ${!showAiOnly || findT('MCP-S03').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                                                <Icons.FileWarning size={14} className="text-red-500"/>
                                            </button>
                                            <button onMouseEnter={() => setActiveThreat(findT('MCP-S05'))} className={`absolute top-2 right-8 p-1 bg-white rounded-full border border-gray-200 hover:bg-gray-50 ${!showAiOnly || findT('MCP-S05').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                                                <Icons.Server size={14} className="text-gray-500"/>
                                            </button>
                                        </div>

                                        <div className="bg-slate-800 p-2 rounded border border-slate-600 relative h-32 mb-2">
                                            <span className="text-[10px] text-slate-400 font-bold">Layer 2: Logic</span>
                                            <button onMouseEnter={() => setActiveThreat(findT('MCP-S01'))} className={`absolute top-8 right-2 p-1.5 bg-slate-700 rounded-full border border-red-500 hover:bg-red-900 ${!showAiOnly || findT('MCP-S01').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                                                <Icons.Terminal size={14} className="text-red-400"/>
                                            </button>
                                            <button onMouseEnter={() => setActiveThreat(findT('MCP-S07'))} className={`absolute bottom-2 left-2 p-1.5 bg-slate-700 rounded-full border border-blue-500 hover:bg-blue-900 ${!showAiOnly || findT('MCP-S07').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                                                <Icons.Shield size={14} className="text-blue-400"/>
                                            </button>
                                            <button onMouseEnter={() => setActiveThreat(findT('MCP-S02'))} className={`absolute bottom-2 right-2 p-1.5 bg-slate-700 rounded-full border border-orange-500 hover:bg-orange-900 ${!showAiOnly || findT('MCP-S02').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                                                <Icons.User size={14} className="text-orange-400"/>
                                            </button>
                                        </div>

                                        <div className="bg-yellow-50 p-2 rounded border border-yellow-200 mb-2 relative">
                                            <span className="text-[10px] text-yellow-800 font-bold">Layer 3: Data</span>
                                            <button onMouseEnter={() => setActiveThreat(findT('MCP-S04'))} className={`absolute top-1 right-2 p-1 bg-white rounded-full border border-yellow-300 hover:bg-yellow-100 ${!showAiOnly || findT('MCP-S04').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                                                <Icons.Lock size={12} className="text-yellow-600"/>
                                            </button>
                                        </div>

                                        <div className="bg-pink-50 p-2 rounded border border-pink-200 relative">
                                            <span className="text-[10px] text-pink-800 font-bold">Layer 4: Deps</span>
                                            <button onMouseEnter={() => setActiveThreat(findT('MCP-S06'))} className={`absolute top-1 right-2 p-1 bg-white rounded-full border border-pink-300 hover:bg-pink-100 ${!showAiOnly || findT('MCP-S06').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                                                <Icons.Database size={12} className="text-pink-600"/>
                                            </button>
                                        </div>

                                        <button onMouseEnter={() => setActiveThreat(findT('MCP-S08'))} className={`absolute top-1/2 -right-3 p-1.5 bg-white rounded-full border border-purple-400 shadow hover:bg-purple-50 ${!showAiOnly || findT('MCP-S08').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                                            <Icons.Activity size={14} className="text-purple-600"/>
                                        </button>
                                    </div>

                                    {/* Connection */}
                                    <div className="absolute top-32 left-[240px] w-40 h-2 bg-slate-300"></div>
                                    <button onMouseEnter={() => setActiveThreat(findT('MCP-C01'))} className={`absolute top-[115px] left-[260px] p-1.5 bg-white rounded-full border border-red-200 hover:bg-red-50 z-20 ${!showAiOnly ? 'opacity-100' : 'opacity-20'}`}>
                                        <Icons.Network size={14} className="text-red-600"/>
                                    </button>
                                    <button onMouseEnter={() => setActiveThreat(findT('MCP-S10'))} className={`absolute top-[115px] left-[320px] p-1.5 bg-white rounded-full border border-teal-200 hover:bg-teal-50 z-20 ${!showAiOnly ? 'opacity-100' : 'opacity-20'}`}>
                                        <Icons.Globe size={14} className="text-teal-600"/>
                                    </button>

                                    {/* External Context */}
                                    <div className="absolute top-48 left-[700px] w-40 h-24 bg-indigo-50 border-2 border-indigo-100 rounded-lg p-3 flex flex-col justify-center items-center shadow-sm">
                                        <div className="text-indigo-900 font-bold text-xs mb-1">External Context</div>
                                        <button onMouseEnter={() => setActiveThreat(findT('MCP-S09'))} className={`absolute -left-3 top-8 p-1.5 bg-white rounded-full border border-indigo-300 shadow hover:bg-indigo-50 ${!showAiOnly || findT('MCP-S09').isAiNative ? 'opacity-100' : 'opacity-20'}`}>
                                            <Icons.Eye size={14} className="text-indigo-600"/>
                                        </button>
                                    </div>
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
                                                <div className="text-[10px] font-bold text-slate-400 uppercase flex items-center gap-1"><Icons.ScanLine size={10} /> AST / Static Rule</div>
                                                <div className="text-xs font-mono text-slate-700 mt-1">{activeThreat.ast_rule}</div>
                                            </div>
                                            <div className="bg-indigo-50 p-2 rounded border border-indigo-100">
                                                <div className="text-[10px] font-bold text-indigo-400 uppercase flex items-center gap-1"><Icons.Brain size={10} /> Semantic / LLM Rule</div>
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

        const App = () => {
            const [currentModule, setCurrentModule] = useState('architecture');

            return (
                <div className="flex flex-col h-screen bg-slate-50 text-slate-800 font-sans overflow-hidden">
                    <div className="bg-white border-b border-slate-200 px-6 py-4 flex justify-between items-center shadow-sm z-10">
                        <div>
                            <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2">
                                <div className="bg-blue-600 text-white p-1 rounded">M</div>
                                Model Context Protocol
                            </h1>
                        </div>
                        <div className="flex bg-slate-100 p-1 rounded-lg border border-slate-200">
                            <button onClick={() => setCurrentModule('architecture')} className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${currentModule === 'architecture' ? 'bg-white shadow text-blue-600 ring-1 ring-slate-200' : 'text-slate-500 hover:text-slate-900'}`}><Icons.Layers size={16} /> Core Architecture</button>
                            <button onClick={() => setCurrentModule('security')} className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${currentModule === 'security' ? 'bg-white shadow text-indigo-600 ring-1 ring-slate-200' : 'text-slate-500 hover:text-slate-900'}`}><Icons.Shield size={16} /> Security & Threats</button>
                        </div>
                    </div>
                    <div className="flex-grow overflow-hidden relative">
                        {currentModule === 'architecture' ? <ArchitectureModule /> : <SecurityModule />}
                    </div>
                </div>
            );
        };

        const root = ReactDOM.createRoot(document.getElementById('root'));
        root.render(<App />);
    </script>
</body>
</html>
