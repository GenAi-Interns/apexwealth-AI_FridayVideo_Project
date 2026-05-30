import { useState, useRef, useEffect } from 'react';
import { Send, Loader2, AlertTriangle, ShieldCheck, Trash2, Lock, AlertOctagon, Info } from 'lucide-react';
import { motion } from 'framer-motion';
import { useAuth } from '../../context/AuthContext';

function SecurityGatewayCard({ msg, isAdmin }) {
  // Normalize status
  const status = (msg.status === 'PASSED' || msg.status === 'PASS') ? 'PASS' : msg.status;
  
  if (!isAdmin) {
    const layer = (msg.triggered_layer || '').toUpperCase();
    const issue = (msg.detected_issue || '').toUpperCase();

    if (status === 'BLOCK') {
      // 1. RBAC / Access Policy Violation
      if (
        layer.includes('POLICY') || 
        issue.includes('ROLE') || 
        issue.includes('DEPT') || 
        issue.includes('ACCESS') || 
        issue.includes('PERMISSION') || 
        msg.risk_score === 0.8
      ) {
        return (
          <div className="w-full max-w-xl border border-rose-500/20 rounded-2xl p-5 bg-rose-50/20 dark:bg-rose-950/15 text-slate-800 dark:text-slate-200">
            <div className="flex items-center gap-2 text-rose-600 dark:text-rose-400 font-bold text-base mb-3">
              <Lock size={18} />
              🔒 Access Restricted
            </div>
            <div className="space-y-4 text-sm leading-relaxed">
              <div>
                <span className="block font-semibold text-[10px] text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">
                  Reason:
                </span>
                <p className="text-slate-700 dark:text-slate-300 font-semibold">You do not have permission to access this information.</p>
              </div>
              <div>
                <span className="block font-semibold text-[10px] text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">
                  What you can do:
                </span>
                <p className="text-slate-600 dark:text-slate-400">Request access through your administrator if this information is required for your role.</p>
              </div>
            </div>
          </div>
        );
      }

      // 2. Secrets Leak (API Key / Passwords)
      if (
        layer.includes('PII') || 
        issue.includes('SECRET') || 
        issue.includes('KEY') || 
        issue.includes('PASSWORD') || 
        issue.includes('CREDENTIAL')
      ) {
        return (
          <div className="w-full max-w-xl border border-rose-500/20 rounded-2xl p-5 bg-rose-50/20 dark:bg-rose-950/15 text-slate-800 dark:text-slate-200">
            <div className="flex items-center gap-2 text-rose-600 dark:text-rose-400 font-bold text-base mb-3">
              <Lock size={18} />
              🔒 Request Blocked
            </div>
            <div className="space-y-4 text-sm leading-relaxed">
              <div>
                <span className="block font-semibold text-[10px] text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">
                  Reason:
                </span>
                <p className="text-slate-700 dark:text-slate-300 font-semibold">Sensitive credentials were detected in your message.</p>
              </div>
              <div>
                <span className="block font-semibold text-[10px] text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">
                  What you can do:
                </span>
                <p className="text-slate-600 dark:text-slate-400">Remove passwords, API keys, tokens, or other confidential credentials before submitting.</p>
              </div>
            </div>
          </div>
        );
      }

      // 3. Prompt Injection (default block)
      return (
        <div className="w-full max-w-xl border border-rose-500/20 rounded-2xl p-5 bg-rose-50/20 dark:bg-rose-950/15 text-slate-800 dark:text-slate-200">
          <div className="flex items-center gap-2 text-rose-600 dark:text-rose-400 font-bold text-base mb-3">
            <Lock size={18} />
            🔒 Request Blocked
          </div>
          <div className="space-y-4 text-sm leading-relaxed">
            <div>
              <span className="block font-semibold text-[10px] text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">
                Reason:
              </span>
              <p className="text-slate-700 dark:text-slate-300 font-semibold">This request attempts to modify or bypass system instructions.</p>
            </div>
            <div>
              <span className="block font-semibold text-[10px] text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">
                What you can do:
              </span>
              <p className="text-slate-600 dark:text-slate-400">Ask your question without requesting access to internal system behavior.</p>
            </div>
          </div>
        </div>
      );
    }

    if (status === 'WARN') {
      // 4. Toxic Language Warning
      if (issue.includes('TOXIC') || issue.includes('LANGUAGE')) {
        return (
          <div className="w-full max-w-xl border border-amber-500/20 rounded-2xl p-5 bg-amber-50/20 dark:bg-amber-950/10 text-slate-800 dark:text-slate-200">
            <div className="flex items-center gap-2 text-amber-600 dark:text-amber-400 font-bold text-base mb-2">
              <AlertTriangle size={18} />
              ⚠ Content Warning
            </div>
            <div className="text-sm space-y-4">
              <p className="text-slate-600 dark:text-slate-400 font-medium">Potentially inappropriate language was detected.</p>
              <p className="text-slate-500 dark:text-slate-500 text-xs">The request was processed safely.</p>
              <div className="border-t border-slate-100 dark:border-slate-800/80 pt-3 mt-3">
                <span className="block font-semibold text-[10px] text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">
                  Summary:
                </span>
                <div className="text-slate-700 dark:text-slate-300 leading-relaxed font-sans whitespace-pre-wrap">
                  {msg.content}
                </div>
              </div>
            </div>
          </div>
        );
      }

      // 5. PII Warning
      return (
        <div className="w-full max-w-xl border border-amber-500/20 rounded-2xl p-5 bg-amber-50/20 dark:bg-amber-950/10 text-slate-800 dark:text-slate-200">
          <div className="flex items-center gap-2 text-amber-600 dark:text-amber-400 font-bold text-base mb-2">
            <AlertTriangle size={18} />
            ⚠ Personal Information Protected
          </div>
          <div className="text-sm space-y-3">
            <p className="text-slate-600 dark:text-slate-400">Sensitive information was detected and automatically masked before processing.</p>
            <div className="border-t border-slate-100 dark:border-slate-800/80 pt-3 mt-3">
              <span className="block font-semibold text-[10px] text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">
                Your response:
              </span>
              <div className="text-slate-700 dark:text-slate-300 leading-relaxed font-sans whitespace-pre-wrap">
                {msg.content}
              </div>
            </div>
          </div>
        </div>
      );
    }

    if (status === 'ERROR') {
      return (
        <div className="w-full max-w-xl border border-orange-500/20 rounded-2xl p-5 bg-orange-50/20 dark:bg-orange-950/10 text-slate-800 dark:text-slate-200">
          <div className="flex items-center gap-2 text-orange-600 dark:text-orange-400 font-bold text-base mb-2">
            <AlertOctagon size={18} />
            ⚠ System Error
          </div>
          <div className="text-sm space-y-3">
            <p className="text-slate-600 dark:text-slate-400 font-semibold">The gateway was unable to complete the request.</p>
            <div className="border-t border-slate-100 dark:border-slate-800/80 pt-3 mt-3">
              <span className="block font-semibold text-[10px] text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-1">
                Details:
              </span>
              <div className="text-slate-700 dark:text-slate-300 font-mono text-xs whitespace-pre-wrap">
                {msg.content}
              </div>
            </div>
          </div>
        </div>
      );
    }
  }

  // Status styling configurations
  const config = {
    PASS: {
      borderColor: 'border-emerald-500/30 dark:border-emerald-500/20',
      bgColor: 'bg-emerald-50/20 dark:bg-emerald-950/10',
      textColor: 'text-slate-800 dark:text-slate-200',
      badgeColor: 'text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-500/20',
      riskBarColor: 'bg-emerald-500 dark:bg-emerald-600',
      icon: ShieldCheck,
      statusText: 'PASS / SECURE',
    },
    WARN: {
      borderColor: 'border-amber-500/30 dark:border-amber-500/20',
      bgColor: 'bg-amber-50/20 dark:bg-amber-950/10',
      textColor: 'text-slate-800 dark:text-slate-200',
      badgeColor: 'text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/40 border-amber-500/20',
      riskBarColor: 'bg-amber-500 dark:bg-amber-600',
      icon: AlertTriangle,
      statusText: 'WARN / MITIGATED',
    },
    BLOCK: {
      borderColor: 'border-rose-500/30 dark:border-rose-500/20',
      bgColor: 'bg-rose-50/20 dark:bg-rose-950/15',
      textColor: 'text-slate-800 dark:text-slate-200',
      badgeColor: 'text-rose-700 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/40 border-rose-500/20',
      riskBarColor: 'bg-rose-500 dark:bg-rose-600',
      icon: Lock,
      statusText: 'BLOCK / INTERCEPTED',
    },
    ERROR: {
      borderColor: 'border-orange-500/30 dark:border-orange-500/20',
      bgColor: 'bg-orange-50/20 dark:bg-orange-950/10',
      textColor: 'text-slate-800 dark:text-slate-200',
      badgeColor: 'text-orange-700 dark:text-orange-400 bg-orange-50 dark:bg-orange-950/40 border-orange-500/20',
      riskBarColor: 'bg-orange-500 dark:bg-orange-600',
      icon: AlertOctagon,
      statusText: 'GATEWAY ERROR',
    }
  };

  const currentConfig = config[status] || config.PASS;
  const IconComponent = currentConfig.icon;
  const riskVal = msg.risk_score !== undefined ? msg.risk_score : 0.0;
  const riskPercent = Math.min(Math.max(riskVal * 100, 0), 100);

  return (
    <div className={`w-full max-w-2xl border rounded-2xl overflow-hidden shadow-md flex flex-col bg-white dark:bg-slate-900/60 ${currentConfig.borderColor}`}>
      {/* Card Header Receipt Style */}
      <div className={`px-4 py-3 border-b flex items-center justify-between ${currentConfig.borderColor} ${currentConfig.bgColor}`}>
        <div className="flex items-center gap-2">
          <span className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${currentConfig.badgeColor}`}>
            <IconComponent size={14} />
            {currentConfig.statusText}
          </span>
        </div>
        <div className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">
          SECURESHIELD GATEWAY RECEIPT
        </div>
      </div>

      {/* Grid of gateway attributes */}
      <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs border-b border-slate-100 dark:border-slate-800/80">
        {/* Risk Score Parameter */}
        <div className="flex flex-col gap-1.5">
          <span className="text-slate-400 dark:text-slate-500 font-semibold uppercase tracking-wider text-[10px]">
            Risk Score Index
          </span>
          <div className="flex items-center gap-3">
            <span className="font-mono font-bold text-slate-700 dark:text-slate-300">
              {riskVal.toFixed(4)}
            </span>
            <div className="flex-1 h-2 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
              <div 
                className={`h-full rounded-full transition-all duration-500 ${currentConfig.riskBarColor}`}
                style={{ width: `${riskPercent}%` }}
              />
            </div>
          </div>
        </div>

        {/* Triggered Layer */}
        <div className="flex flex-col gap-1">
          <span className="text-slate-400 dark:text-slate-500 font-semibold uppercase tracking-wider text-[10px]">
            Triggered Security Layer
          </span>
          <span className="font-semibold text-slate-700 dark:text-slate-300">
            {msg.triggered_layer && msg.triggered_layer !== 'None' ? (
              <span className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 font-mono text-[11px]">
                {msg.triggered_layer}
              </span>
            ) : (
              <span className="text-slate-400">None (Pipeline Clear)</span>
            )}
          </span>
        </div>

        {/* Detected Issue */}
        <div className="flex flex-col gap-1">
          <span className="text-slate-400 dark:text-slate-500 font-semibold uppercase tracking-wider text-[10px]">
            Detected Threat/Issue
          </span>
          <span className="text-slate-700 dark:text-slate-300 font-medium font-mono text-[11px]">
            {msg.detected_issue && msg.detected_issue !== 'None' ? (
              <span className="text-rose-600 dark:text-rose-400 font-semibold">{msg.detected_issue}</span>
            ) : (
              <span className="text-slate-400">None</span>
            )}
          </span>
        </div>

        {/* Action Taken */}
        <div className="flex flex-col gap-1">
          <span className="text-slate-400 dark:text-slate-500 font-semibold uppercase tracking-wider text-[10px]">
            Mitigation / Action Taken
          </span>
          <span className="text-slate-700 dark:text-slate-300 font-medium">
            {msg.action_taken || (status === 'PASS' ? 'Passed to LLM' : 'N/A')}
          </span>
        </div>
      </div>

      {/* Suggestion / Remediation note */}
      {msg.suggestion && msg.suggestion !== 'None' && (
        <div className="px-4 py-2.5 bg-slate-50/50 dark:bg-slate-900/30 border-b border-slate-100 dark:border-slate-800/80 text-[11px] flex gap-2 items-start text-slate-600 dark:text-slate-400">
          <Info size={14} className="text-slate-400 dark:text-slate-500 flex-shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-slate-700 dark:text-slate-300 mr-1">Remediation:</span>
            {msg.suggestion}
          </div>
        </div>
      )}

      {/* Response Box */}
      <div className="p-4 bg-slate-50/20 dark:bg-slate-950/20">
        <span className="text-slate-400 dark:text-slate-500 font-semibold uppercase tracking-wider text-[10px] block mb-2">
          Payload Response
        </span>
        <div className="text-sm text-slate-800 dark:text-slate-200 leading-relaxed font-mono whitespace-pre-wrap">
          {msg.content}
        </div>
      </div>

      {/* Diagnostic Footer */}
      <div className="px-4 py-2 bg-slate-50 dark:bg-slate-900/80 border-t border-slate-100 dark:border-slate-800 text-[10px] text-slate-400 dark:text-slate-500 flex justify-between items-center">
        <span>
          {status === 'BLOCK' ? '🛡️ Policy Enforcement Block' : (status === 'WARN' ? '⚠️ Sensitivity Sanitization Active' : '✅ Compliant Transaction')}
        </span>
        <span>
          {isAdmin ? 'Scope: Admin Diagnostics' : 'Scope: Employee Gateway'}
        </span>
      </div>
    </div>
  );
}

export default function ChatBox({ messages, onSendMessage, onClearHistory, loading }) {
  const [input, setInput] = useState('');
  const endRef = useRef(null);
  const { user } = useAuth();
  const isAdmin = user?.role === 'Admin';

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if(input.trim()) {
      onSendMessage(input);
      setInput('');
    }
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-white dark:bg-slate-950 relative">
      {/* Header with Clear Action */}
      <div className="h-14 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between px-6 bg-white/50 dark:bg-slate-950/50 backdrop-blur-md z-10">
        <div className="flex items-center gap-2">
          <ShieldCheck className="text-cyan-500" size={18} />
          <span className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Security Console</span>
        </div>
        {messages.length > 0 && (
          <button 
            onClick={onClearHistory}
            className="flex items-center gap-2 text-xs font-medium text-slate-500 hover:text-rose-500 transition-colors"
            title="Clear Chat History"
          >
            <Trash2 size={14} />
            <span>Clear History</span>
          </button>
        )}
      </div>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 md:p-6 space-y-6">
        {messages.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-slate-500">
            <ShieldCheck size={48} className="text-slate-800 mb-4" />
            <p className="text-lg">Send a prompt. SecureShield will analyze it.</p>
          </div>
        )}

        {messages.map((msg, idx) => (
          <motion.div 
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            key={idx} 
            className={`flex flex-col max-w-[85%] ${msg.role === 'user' ? 'self-end items-end ml-auto' : 'self-start items-start'}`}
          >
            {msg.role === 'system' && (msg.status === 'WARN' || msg.status === 'BLOCK' || msg.status === 'ERROR') ? (
              <SecurityGatewayCard msg={msg} isAdmin={isAdmin} />
            ) : (
              <div className={`p-4 rounded-2xl shadow-sm border flex flex-col gap-2 ${
                msg.role === 'user' 
                  ? 'bg-cyan-600/10 text-cyan-900 dark:text-cyan-50 border-cyan-500/20 rounded-tr-sm' 
                  : 'bg-slate-50 dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 rounded-tl-sm'
              }`}>
                {msg.role === 'system' && !isAdmin && (
                  <div className="flex items-center gap-1.5 text-xs font-bold text-emerald-600 dark:text-emerald-400 mb-1 border-b border-slate-100 dark:border-slate-800/80 pb-1.5">
                    ✅ Response Generated
                  </div>
                )}
                <p className="whitespace-pre-wrap leading-relaxed text-sm font-sans">{msg.content}</p>
              </div>
            )}
          </motion.div>
        ))}
        {loading && (
           <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex items-center gap-3 text-cyan-600 dark:text-cyan-500 self-start p-4 bg-slate-50 dark:bg-slate-900 rounded-2xl rounded-tl-sm border border-slate-200 dark:border-slate-800">
             <Loader2 size={18} className="animate-spin" /> Analyzing payload through pipeline...
           </motion.div>
        )}
        <div ref={endRef} />
      </div>

      {/* Input Area */}
      <div className="p-4 border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950/80 backdrop-blur-md">
        <form onSubmit={handleSubmit} className="relative flex items-center max-w-4xl mx-auto">
          <input 
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={loading}
            placeholder="Test a payload or prompt..."
            className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl py-4 pl-4 pr-16 text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 transition-all disabled:opacity-50"
          />
          <button 
            type="submit"
            disabled={!input.trim() || loading}
            className="absolute right-2 p-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50 disabled:bg-slate-200 dark:disabled:bg-slate-800 disabled:text-slate-400 dark:disabled:text-slate-500"
          >
            <Send size={18} />
          </button>
        </form>
      </div>
    </div>
  );
}
