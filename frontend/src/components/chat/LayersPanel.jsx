import { motion } from 'framer-motion';
import { ShieldAlert, ShieldCheck, CheckCircle2, CircleDashed, Loader2, XCircle, ShieldOff } from 'lucide-react';

export default function LayersPanel({ currentStatus, blockedLayer, settings }) {
  // Ordered pipeline of your exact backend
  const layers = [
    { id: 'input', name: 'Input Guard', blockIndicator: 'INPUT_GUARD' },
    { id: 'policy', name: 'Policy Engine', blockIndicator: 'POLICY_ENGINE' },
    { id: 'toxicity', name: 'Toxicity Guard', blockIndicator: 'TOXICITY_GUARD' },
    { id: 'semantic', name: 'Semantic Guard', blockIndicator: 'SEMANTIC_GUARD' },
    { id: 'pii_in', name: 'PII Redaction (In)', blockIndicator: 'PII_GUARD' },
    { id: 'llm', name: 'LLM Brain', blockIndicator: 'SYSTEM' },
    { id: 'pii_out', name: 'Output Guard', blockIndicator: 'OUTPUT_GUARDRAILS' },
  ];

  // Determine the state of each layer based on the backend response
  const getLayerState = (layer) => {
    // Check if layer is disabled in administrator settings
    const isBypassed = (layerId) => {
      if (!settings) return false;
      if (layerId === 'input') return settings.input_guard === false;
      if (layerId === 'policy') return settings.policy_engine === false;
      if (layerId === 'toxicity') return settings.toxicity_guard === false;
      if (layerId === 'pii_in' || layerId === 'pii_out') return settings.pii_guard === false;
      return false;
    };

    if (isBypassed(layer.id)) {
      return { 
        status: 'bypassed', 
        color: 'text-slate-400 dark:text-slate-600', 
        bg: 'bg-slate-100/10 dark:bg-slate-900/10 opacity-50 border-dashed border-slate-200 dark:border-slate-800' 
      };
    }

    if (currentStatus === 'idle') return { status: 'idle', color: 'text-slate-500', bg: 'bg-slate-100/30 dark:bg-slate-800/30' };
    if (currentStatus === 'processing') return { status: 'loading', color: 'text-cyan-500', bg: 'bg-cyan-500/10 border-cyan-500/30' };
    
    if (currentStatus === 'BLOCK' || currentStatus === 'BLOCKED' || currentStatus === 'ERROR') {
      const isMyBlock = 
        (layer.id === 'input' && blockedLayer === 'INPUT_GUARD') ||
        (layer.id === 'policy' && blockedLayer === 'POLICY_ENGINE') ||
        (layer.id === 'toxicity' && blockedLayer === 'TOXICITY_GUARD') ||
        (layer.id === 'semantic' && blockedLayer === 'SEMANTIC_GUARD') ||
        (layer.id === 'pii_in' && blockedLayer === 'PII_GUARD') ||
        (layer.id === 'pii_out' && blockedLayer === 'OUTPUT_GUARDRAILS');
        
      if (isMyBlock) {
        return { status: 'blocked', color: 'text-rose-500', bg: 'bg-rose-500/10 border-rose-500/30' };
      }
      
      // If it's a generic system error, check if this is system block
      if (blockedLayer === 'SYSTEM' && layer.id === 'llm') {
        return { status: 'blocked', color: 'text-orange-500', bg: 'bg-orange-500/10 border-orange-500/30' };
      }

      // Determine ordering
      const layerOrder = ['input', 'policy', 'toxicity', 'semantic', 'pii_in', 'llm', 'pii_out'];
      const blockedLayerIdMap = {
        'INPUT_GUARD': 'input',
        'POLICY_ENGINE': 'policy',
        'TOXICITY_GUARD': 'toxicity',
        'SEMANTIC_GUARD': 'semantic',
        'PII_GUARD': 'pii_in',
        'OUTPUT_GUARDRAILS': 'pii_out',
        'SYSTEM': 'llm'
      };
      
      const blockedLayerId = blockedLayerIdMap[blockedLayer] || 'llm';
      const blockIndex = layerOrder.indexOf(blockedLayerId);
      const myIndex = layerOrder.indexOf(layer.id);
      
      if (myIndex < blockIndex) {
        return { status: 'passed', color: 'text-emerald-500', bg: 'bg-emerald-500/10 border-emerald-500/30' };
      } else {
        return { status: 'skipped', color: 'text-slate-600', bg: 'bg-slate-50/50 dark:bg-slate-900/50' };
      }
    }

    if (currentStatus === 'PASS' || currentStatus === 'PASSED' || currentStatus === 'WARN') {
      return { status: 'passed', color: 'text-emerald-500', bg: 'bg-emerald-500/10 border-emerald-500/30' };
    }

    return { status: 'idle', color: 'text-slate-500', bg: 'bg-slate-100/30 dark:bg-slate-800/30' };
  };

  const getIcon = (status) => {
    switch(status) {
      case 'idle': return <CircleDashed size={18} />;
      case 'loading': return <Loader2 size={18} className="animate-spin" />;
      case 'passed': return <CheckCircle2 size={18} />;
      case 'blocked': return <XCircle size={18} />;
      case 'skipped': return <CircleDashed size={18} className="opacity-50" />;
      case 'bypassed': return <ShieldOff size={18} className="opacity-40" />;
      default: return <CircleDashed size={18} />;
    }
  };

  return (
    <div className="w-72 bg-slate-50 dark:bg-slate-900/80 border-r border-slate-200 dark:border-slate-800 flex flex-col h-full overflow-hidden">
      <div className="p-3 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-slate-900">
        <h2 className="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
          <ShieldAlert size={18} className="text-cyan-500" /> Security Pipeline
        </h2>
      </div>

      <div className="p-3 flex-1 overflow-y-auto no-scrollbar">
        <div className="space-y-1.5 relative">
          {/* Vertical connecting line */}
          <div className="absolute left-6 top-6 bottom-6 w-0.5 bg-slate-200 dark:bg-slate-800/50 z-0"></div>
          
          {layers.map((layer, index) => {
            const state = getLayerState(layer);
            return (
              <motion.div 
                key={layer.id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className={`relative z-10 flex items-center gap-3 p-2 rounded-xl border border-transparent transition-all duration-500 ${state.bg}`}
              >
                <div className={`flex-shrink-0 bg-white dark:bg-slate-950 rounded-full p-1 ${state.color}`}>
                  {getIcon(state.status)}
                </div>
                <div className="flex-1">
                  <p className={`text-sm font-medium ${state.status === 'skipped' || state.status === 'bypassed' ? 'text-slate-500' : 'text-slate-800 dark:text-slate-200'}`}>
                    {layer.name}
                  </p>
                  <p className="text-xs text-slate-500 capitalize">{state.status}</p>
                </div>
              </motion.div>
            )
          })}
        </div>
      </div>
    </div>
  );
}
