import { useState, useEffect } from 'react';
import api from '../api/axios';
import LayersPanel from '../components/chat/LayersPanel';
import ChatBox from '../components/chat/ChatBox';
import { useAuth } from '../context/AuthContext';

export default function ChatPage() {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);
  const [pipelineStatus, setPipelineStatus] = useState('idle'); // idle, processing, PASS, WARN, BLOCK, ERROR
  const [blockedReason, setBlockedReason] = useState(null);
  const [blockedLayer, setBlockedLayer] = useState(null);
  const [settings, setSettings] = useState(null);
  const { user } = useAuth();

  const isAdmin = user?.role === 'Admin';

  useEffect(() => {
    // Load historical chats on page mount
    api.get('/chat/history')
      .then(res => {
        setMessages(res.data);
        // Restore last gateway status and layer state on load
        const sysMsgs = res.data.filter(m => m.role === 'system');
        if (sysMsgs.length > 0) {
          const lastSys = sysMsgs[sysMsgs.length - 1];
          setPipelineStatus(lastSys.status);
          setBlockedReason(lastSys.content);
          setBlockedLayer(lastSys.triggered_layer || null);
        }
      })
      .catch(err => console.error("Failed to load chat history:", err));

    // Load active settings to dynamically display active/disabled pipeline layers
    if (isAdmin) {
      api.get('/settings')
        .then(res => {
          setSettings(res.data);
        })
        .catch(err => console.error("Failed to load settings:", err));
    }
  }, [isAdmin]);

  const handleSendMessage = async (input) => {
    // 1. Add user message to UI immediately
    const userMsg = { role: 'user', content: input };
    setMessages(prev => [...prev, userMsg]);

    // 2. Set processing state
    setLoading(true);
    setPipelineStatus('processing');
    setBlockedReason(null);
    setBlockedLayer(null);

    try {
      // 3. Hit the backend
      const res = await api.post(`/chat`, { message: input });
      const data = res.data;

      // 4. Handle response
      setPipelineStatus(data.status);
      setBlockedReason(data.response);
      setBlockedLayer(data.triggered_layer || null);

      setMessages(prev => [...prev, {
        role: 'system',
        content: data.response,
        status: data.status,
        risk_score: data.risk_score,
        detected_issue: data.detected_issue,
        triggered_layer: data.triggered_layer,
        action_taken: data.action_taken,
        suggestion: data.suggestion
      }]);

    } catch (err) {
      const errorDetail = err.response?.data?.detail || err.message || 'Connection Error';
      console.error("Chat Error:", err);
      setPipelineStatus('ERROR');
      setBlockedReason(errorDetail);
      setBlockedLayer('SYSTEM');
      setMessages(prev => [...prev, {
        role: 'system',
        content: `System error during payload analysis: ${errorDetail}`,
        status: 'ERROR',
        risk_score: 1.0,
        detected_issue: 'Gateway Connection Failure',
        triggered_layer: 'SYSTEM',
        action_taken: 'Connection Terminated',
        suggestion: 'Ensure backend server is running and accessible.'
      }]);
    } finally {
      setLoading(false);
    }
  };

  const handleClearHistory = async () => {
    if (!window.confirm("Are you sure you want to clear your chat history? This cannot be undone.")) return;

    try {
      await api.delete('/chat/history');
      setMessages([]);
    } catch (err) {
      console.error("Failed to clear history:", err);
      alert("Failed to clear chat history. See console for details.");
    }
  };

  return (
    <div className="flex h-full w-full bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
      {isAdmin && <LayersPanel currentStatus={pipelineStatus} blockedLayer={blockedLayer} settings={settings} />}
      <ChatBox
        messages={messages}
        onSendMessage={handleSendMessage}
        onClearHistory={handleClearHistory}
        loading={loading}
      />
    </div>
  );
}
