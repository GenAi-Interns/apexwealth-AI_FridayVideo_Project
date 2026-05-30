import { useState, useEffect } from 'react';
import { Settings2, ShieldCheck, Database, Server, Loader2, CheckCircle2, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import api from '../api/axios';

export default function SettingsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'Admin';

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveStatus, setSaveStatus] = useState(''); // 'saving', 'saved', 'error' or ''

  const [layers, setLayers] = useState({
    inputGuard: true,
    policyEngine: true,
    toxicityGuard: true,
    piiGuard: true,
  });

  const [provider, setProvider] = useState('Google Gemini (Current)');
  const [failoverNode, setFailoverNode] = useState('Groq API');
  const [logFailed, setLogFailed] = useState(true);
  const [anonymize, setAnonymize] = useState(false);

  useEffect(() => {
    const fetchSettings = async () => {
      try {
        setLoading(true);
        const res = await api.get('/settings');
        const data = res.data;
        setLayers({
          inputGuard: data.input_guard ?? true,
          policyEngine: data.policy_engine ?? true,
          toxicityGuard: data.toxicity_guard ?? true,
          piiGuard: data.pii_guard ?? true,
        });
        setProvider(data.provider ?? 'Google Gemini (Current)');
        setFailoverNode(data.failover_node ?? 'Groq API');
        setLogFailed(data.log_failed ?? true);
        setAnonymize(data.anonymize ?? false);
      } catch (err) {
        console.error('Failed to load settings:', err);
      } finally {
        setLoading(false);
      }
    };
    if (isAdmin) {
      fetchSettings();
    } else {
      setLoading(false);
    }
  }, [isAdmin]);

  const saveSettings = async (updatedFields) => {
    if (!isAdmin) return;
    try {
      setSaving(true);
      setSaveStatus('saving');
      
      const payload = {
        input_guard: updatedFields.layers?.inputGuard ?? layers.inputGuard,
        policy_engine: updatedFields.layers?.policyEngine ?? layers.policyEngine,
        toxicity_guard: updatedFields.layers?.toxicityGuard ?? layers.toxicityGuard,
        pii_guard: updatedFields.layers?.piiGuard ?? layers.piiGuard,
        provider: updatedFields.provider ?? provider,
        failover_node: updatedFields.failoverNode ?? failoverNode,
        log_failed: updatedFields.hasOwnProperty('logFailed') ? updatedFields.logFailed : logFailed,
        anonymize: updatedFields.hasOwnProperty('anonymize') ? updatedFields.anonymize : anonymize,
      };

      await api.post('/settings', payload);
      setSaveStatus('saved');
      setTimeout(() => {
        setSaveStatus('');
      }, 3000);
    } catch (err) {
      console.error('Failed to save settings:', err);
      setSaveStatus('error');
    } finally {
      setSaving(false);
    }
  };

  const toggleLayer = (layerKey) => {
    const updatedLayers = { ...layers, [layerKey]: !layers[layerKey] };
    setLayers(updatedLayers);
    saveSettings({ layers: updatedLayers });
  };

  const handleProviderChange = (e) => {
    const val = e.target.value;
    setProvider(val);
    saveSettings({ provider: val });
  };

  const handleFailoverChange = (e) => {
    const val = e.target.value;
    setFailoverNode(val);
    saveSettings({ failoverNode: val });
  };

  const handleCheckboxChange = (type) => {
    if (type === 'logFailed') {
      const val = !logFailed;
      setLogFailed(val);
      saveSettings({ logFailed: val });
    } else if (type === 'anonymize') {
      const val = !anonymize;
      setAnonymize(val);
      saveSettings({ anonymize: val });
    }
  };

  if (loading) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <Loader2 className="animate-spin text-cyan-500" size={36} />
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-8 bg-white dark:bg-slate-950 text-slate-800 dark:text-slate-200">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-2">
            <Settings2 className="text-cyan-500" /> Gateway Configuration
          </h1>
          <p className="text-slate-600 dark:text-slate-400">Manage security layers, models, and API integrations.</p>
        </div>

        {/* Sync Status Toast/Badge */}
        {saveStatus && (
          <div className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium border self-start transition-all duration-300 ${
            saveStatus === 'saving' 
              ? 'bg-cyan-500/10 text-cyan-500 border-cyan-500/30' 
              : saveStatus === 'saved'
              ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30'
              : 'bg-rose-500/10 text-rose-500 border-rose-500/30'
          }`}>
            {saveStatus === 'saving' && <Loader2 size={16} className="animate-spin" />}
            {saveStatus === 'saved' && <CheckCircle2 size={16} />}
            {saveStatus === 'error' && <AlertCircle size={16} />}
            <span className="capitalize">{saveStatus === 'saving' ? 'Saving changes...' : saveStatus === 'saved' ? 'Settings saved' : 'Failed to save'}</span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        
        {/* Left Column: Security Layers */}
        <div className="col-span-1 md:col-span-2 space-y-6">
          
          <div className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
              <ShieldCheck size={20} className="text-emerald-500"/> Pipeline Layers
            </h2>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-6">Dynamically toggle which security checks are performed during the Chain of Responsibility workflow.</p>
            
            <div className="space-y-4">
              {Object.entries(layers).map(([key, isActive]) => {
                let description = "Evaluates payloads before LLM inference.";
                if (key === "inputGuard") description = "Performs regex threat matching and fast-track evaluation.";
                if (key === "policyEngine") description = "Enforces role and department policies (RBAC rules).";
                if (key === "toxicityGuard") description = "Scans incoming queries for toxic, offensive, or unsafe language.";
                if (key === "piiGuard") description = "Detects and redacts sensitive information (emails, secrets).";

                return (
                  <div key={key} className="flex items-center justify-between p-4 bg-white/50 dark:bg-slate-950/50 border border-slate-200 dark:border-slate-800 rounded-xl hover:border-slate-300 dark:hover:border-slate-700/80 transition-colors">
                    <div>
                      <h3 className="font-medium text-slate-800 dark:text-slate-200 capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}</h3>
                      <p className="text-xs text-slate-500">{description}</p>
                    </div>
                    
                    <button 
                      onClick={() => isAdmin && toggleLayer(key)}
                      disabled={!isAdmin || saving}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-all disabled:opacity-50 disabled:cursor-not-allowed ${isActive ? 'bg-cyan-500' : 'bg-slate-700'}`}
                    >
                      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${isActive ? 'translate-x-6' : 'translate-x-1'}`} />
                    </button>
                  </div>
                );
              })}
              {!isAdmin && <p className="text-xs text-rose-500 mt-2">Only System Admins can modify pipeline layers.</p>}
            </div>
          </div>

        </div>

        {/* Right Column: API & Models */}
        <div className="space-y-6">
          <div className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
             <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
              <Server size={20} className="text-purple-500"/> LLM Engine
            </h2>
            
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Provider</label>
                <div className="relative">
                  <select 
                    value={provider} 
                    onChange={handleProviderChange} 
                    disabled={!isAdmin || saving} 
                    className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-2.5 text-sm text-slate-800 dark:text-slate-200 outline-none focus:border-cyan-500 transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    <option value="Google Gemini (Current)">Google Gemini (Current)</option>
                    <option value="OpenAI API">OpenAI API</option>
                    <option value="Local Ollama">Local Ollama</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Failover Node</label>
                <div className="relative">
                  <select 
                    value={failoverNode} 
                    onChange={handleFailoverChange} 
                    disabled={!isAdmin || saving} 
                    className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-2.5 text-sm text-slate-800 dark:text-slate-200 outline-none focus:border-cyan-500 transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    <option value="Groq API">Groq API</option>
                    <option value="None">None</option>
                  </select>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
             <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
              <Database size={20} className="text-amber-500"/> Data Retention
            </h2>
            <div className="space-y-4">
               <label className="flex items-center gap-3 cursor-pointer group">
                 <input 
                   type="checkbox" 
                   checked={logFailed} 
                   onChange={() => handleCheckboxChange('logFailed')} 
                   disabled={!isAdmin || saving} 
                   className="rounded border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-slate-900 cursor-pointer disabled:opacity-50 w-4 h-4" 
                 />
                 <span className="text-sm text-slate-700 dark:text-slate-300 group-hover:text-slate-900 dark:group-hover:text-white transition-colors">Log all failed requests</span>
               </label>
               <label className="flex items-center gap-3 cursor-pointer group">
                 <input 
                   type="checkbox" 
                   checked={anonymize} 
                   onChange={() => handleCheckboxChange('anonymize')} 
                   disabled={!isAdmin || saving} 
                   className="rounded border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-slate-900 cursor-pointer disabled:opacity-50 w-4 h-4" 
                 />
                 <span className="text-sm text-slate-700 dark:text-slate-300 group-hover:text-slate-900 dark:group-hover:text-white transition-colors">Anonymize completely</span>
               </label>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
