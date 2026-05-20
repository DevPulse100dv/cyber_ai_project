import React, { useEffect, useState, useRef } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Users,
  Activity,
  AlertTriangle,
  RefreshCw,
  Search,
  Clock,
  FileText,
  Newspaper,
  PhoneCall,
  LayoutDashboard,
  ArrowRight,
  Upload,
  Lock,
  Globe,
  Trash2,
  Info,
  Terminal,
  Cpu,
  Fingerprint,
  Smartphone,
  MessageSquare,
  ShieldQuestion
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts';
import { motion, AnimatePresence } from 'framer-motion';

const COLORS = ['#10b981', '#3b82f6', '#8b5cf6', '#ef4444', '#f59e0b'];

// --- SHARED COMPONENTS ---


const LoadingStep = ({ text, delay }) => (
  <motion.div
    initial={{ opacity: 0, x: -10 }}
    animate={{ opacity: 1, x: 0 }}
    transition={{ delay }}
    className="flex items-center gap-3 text-[10px] font-mono text-emerald-500/60 uppercase tracking-widest"
  >
    <div className="w-1 h-1 bg-emerald-500 rounded-full animate-pulse" />
    {text}
  </motion.div>
);

// --- VIEWS ---

export default function App() {
  const [initializing, setInitializing] = useState(true);
  const [view, setView] = useState('LANDING'); // LANDING, PORTAL, ADMIN
  const [stats, setStats] = useState(null);
  const [recentLogs, setRecentLogs] = useState([]);
  const [news, setNews] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const [statsRes, logsRes, newsRes] = await Promise.all([
        fetch('http://localhost:3000/api/stats'),
        fetch('http://localhost:3000/api/recent'),
        fetch('http://localhost:3000/api/news')
      ]);
      setStats(await statsRes.json());
      setRecentLogs(await logsRes.json());
      setNews(await newsRes.json());
    } catch (err) {
      console.error('Failed to fetch:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    // SPEED UP: Refresh every 1 second for real-time demo effect
    const interval = setInterval(fetchData, 1000);
    // Intro animation timer
    const timer = setTimeout(() => setInitializing(false), 3000);
    return () => { clearInterval(interval); clearTimeout(timer); };
  }, []);

  return (
    <div className="min-h-screen bg-[#05080f] text-slate-200 selection:bg-emerald-500/30 relative overflow-hidden font-sans">
      <AnimatePresence mode="wait">
        {initializing ? (
          <IntroAnimation key="intro" />
        ) : (
          <motion.div key="main" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="relative flex flex-col min-h-screen">
            {/* Background Orbs */}
            <div className="fixed top-[-20%] left-[-10%] w-[60%] h-[60%] rounded-full bg-emerald-500/5 blur-[120px] pointer-events-none" />
            <div className="fixed bottom-[-20%] right-[-10%] w-[60%] h-[60%] rounded-full bg-blue-600/5 blur-[120px] pointer-events-none" />

            <Header setView={setView} currentView={view} />

            <main className="flex-1 relative z-10 pt-20">
              <AnimatePresence mode="wait">
                {view === 'LANDING' && <LandingView key="landing" setView={setView} />}
                {view === 'PORTAL' && <PortalView key="portal" setView={setView} news={news} />}
                {view === 'ADMIN' && <AdminView key="admin" setView={setView} stats={stats} recentLogs={recentLogs} />}
                {view === 'DEMO' && <DemoView key="demo" setView={setView} />}
                {view === 'HELP' && <HelpView key="help" setView={setView} />}
              </AnimatePresence>
            </main>

            <Footer />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ── INTRO ANIMATION ──────────────────────────────────────────────────────────
function IntroAnimation() {
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setProgress(p => (p >= 100 ? 100 : p + 2));
    }, 40);
    return () => clearInterval(interval);
  }, []);

  return (
    <motion.div
      exit={{ opacity: 0, scale: 1.1 }}
      className="fixed inset-0 z-[100] bg-[#05080f] flex flex-col items-center justify-center p-6"
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.8 }}
        animate={{ opacity: 1, scale: 1 }}
        className="relative mb-12"
      >
        <div className="absolute inset-0 bg-emerald-500 blur-2xl opacity-20 rounded-full animate-pulse" />
        <ShieldAlert className="h-24 w-24 text-emerald-500 relative z-10" />
      </motion.div>

      <div className="w-full max-w-md">
        <div className="flex justify-between items-end mb-2">
          <div className="space-y-1">
            <h2 className="text-emerald-500 font-mono text-sm tracking-tighter">AGENTIC_AI_INITIALIZING...</h2>
            <p className="text-slate-500 font-mono text-[10px]">VERIFYING SECURITY_PROTOCOLS</p>
          </div>
          <span className="text-emerald-500 font-mono text-xl font-bold">{progress}%</span>
        </div>
        <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden border border-white/5">
          <motion.div
            className="h-full bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,0.5)]"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      <div className="mt-12 grid grid-cols-3 gap-8 opacity-20">
        <Cpu className="h-6 w-6 text-slate-500 animate-bounce" />
        <Terminal className="h-6 w-6 text-slate-500 animate-pulse" />
        <Fingerprint className="h-6 w-6 text-slate-500 animate-bounce" />
      </div>
    </motion.div>
  );
}

// ── HEADER & FOOTER ──────────────────────────────────────────────────────────
function Header({ setView, currentView }) {
  return (
    <header className="fixed top-0 left-0 right-0 z-50 bg-[#05080f]/60 backdrop-blur-xl border-b border-white/5 px-6 py-4">
      <div className="max-w-7xl mx-auto flex justify-between items-center">
        <button onClick={() => setView('LANDING')} className="flex items-center gap-3 group">
          <div className="p-2 bg-emerald-500/10 rounded-lg border border-emerald-500/20 group-hover:scale-110 transition-transform">
            <ShieldCheck className="h-6 w-6 text-emerald-500" />
          </div>
          <span className="font-black text-xl tracking-tighter text-white">FRAUD_DEFENDER</span>
        </button>

        <nav className="hidden md:flex items-center gap-6">
          <HeaderLink active={currentView === 'LANDING'} onClick={() => setView('LANDING')} label="Home" />
          <HeaderLink active={currentView === 'DEMO'} onClick={() => setView('DEMO')} label="Live Demo" />
          <HeaderLink active={currentView === 'PORTAL'} onClick={() => setView('PORTAL')} label="Public Portal" />
          <HeaderLink active={currentView === 'ADMIN'} onClick={() => setView('ADMIN')} label="Admin SOC" />
          <button
            onClick={() => setView('HELP')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${currentView === 'HELP' ? 'bg-red-500 text-white shadow-[0_0_20px_rgba(239,68,68,0.3)]' : 'text-red-400 hover:bg-red-500/10 border border-red-500/20'}`}
          >
            <PhoneCall className="h-4 w-4" /> Emergency
          </button>
        </nav>

        <div className="flex items-center gap-4">
          <div className="hidden sm:flex items-center gap-2 px-3 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-full">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-[10px] font-bold text-emerald-500 uppercase tracking-widest">System Online</span>
          </div>
        </div>
      </div>
    </header>
  );
}

function HeaderLink({ active, onClick, label }) {
  return (
    <button
      onClick={onClick}
      className={`text-sm font-bold tracking-tight transition-colors ${active ? 'text-emerald-500' : 'text-slate-400 hover:text-white'}`}
    >
      {label}
    </button>
  );
}

function Footer() {
  return (
    <footer className="relative z-10 bg-[#05080f] border-t border-white/5 py-12 px-6 mt-auto">
      <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-12">
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-emerald-500" />
            <span className="font-black tracking-tighter text-white text-lg">CYBER_GUARDIAN</span>
          </div>
          <p className="text-sm text-slate-500 leading-relaxed max-w-xs">
            Advanced agentic AI infrastructure for real-time fraud interception and threat intelligence.
            Protecting the digital frontier.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-8">
          <div className="space-y-4">
            <h4 className="text-xs font-bold text-white uppercase tracking-widest">Resources</h4>
            <ul className="text-sm text-slate-500 space-y-2">
              <li className="hover:text-emerald-500 cursor-pointer">Live News</li>
              <li className="hover:text-emerald-500 cursor-pointer">Helplines</li>
              <li className="hover:text-emerald-500 cursor-pointer">API Docs</li>
            </ul>
          </div>
          <div className="space-y-4">
            <h4 className="text-xs font-bold text-white uppercase tracking-widest">System</h4>
            <ul className="text-sm text-slate-500 space-y-2">
              <li className="hover:text-emerald-500 cursor-pointer">Node Status</li>
              <li className="hover:text-emerald-500 cursor-pointer">AI Logs</li>
              <li className="hover:text-emerald-500 cursor-pointer">Privacy</li>
            </ul>
          </div>
        </div>

        <div className="space-y-4">
          <h4 className="text-xs font-bold text-white uppercase tracking-widest">Department Of Defense</h4>
          <div className="p-4 bg-white/5 rounded-2xl border border-white/5">
            <p className="text-[10px] text-slate-400 font-mono">
              HASH: 0x82FA...21E<br />
              VER: 3.1.0-STABLE<br />
              ENV: AGENTIC_PROD
            </p>
          </div>
        </div>
      </div>
      <div className="max-w-7xl mx-auto mt-12 pt-8 border-t border-white/5 text-center text-[10px] text-slate-600 font-mono tracking-widest uppercase">
        © 2026 Agentic Fraud Defender | Integrated Security Infrastructure
      </div>
    </footer>
  );
}

// ── LANDING VIEW ────────────────────────────────────────────────────────────
function LandingView({ setView }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }}
      className="flex flex-col items-center justify-center min-h-[70vh] p-6"
    >
      <motion.div
        initial={{ y: -20, opacity: 0 }} animate={{ y: 0, opacity: 1 }}
        className="text-center max-w-3xl mb-20"
      >
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[10px] font-bold tracking-[0.2em] mb-8 uppercase">
          <Globe className="h-3 w-3" />
          Autonomous Threat Detection Active
        </div>
        <h1 className="text-7xl md:text-9xl font-black tracking-tighter mb-6 bg-gradient-to-b from-white via-white to-white/20 bg-clip-text text-transparent leading-none">
          CYBER <br /> DEFENDER
        </h1>
        <p className="text-lg text-slate-400 mb-12 max-w-xl mx-auto">
          The next generation of fraud prevention. Using a multi-agent AI pipeline
          to identify and neutralize scams before they reach the victim.
        </p>

        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <button
            onClick={() => setView('PORTAL')}
            className="px-8 py-4 bg-emerald-600 hover:bg-emerald-500 text-white rounded-2xl font-black text-sm tracking-widest transition-all hover:scale-105 shadow-[0_0_20px_rgba(16,185,129,0.3)]"
          >
            PUBLIC PORTAL
          </button>
          <button
            onClick={() => setView('ADMIN')}
            className="px-8 py-4 bg-white/5 hover:bg-white/10 border border-white/10 text-white rounded-2xl font-black text-sm tracking-widest transition-all"
          >
            ADMIN CONSOLE
          </button>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full max-w-6xl">
        <FeatureCard icon={<Search />} title="AI Scanning" desc="Deep analysis of messages and links." />
        <FeatureCard icon={<Lock />} title="APK Guard" desc="Automatic extraction and risk scoring." />
        <FeatureCard icon={<Activity />} title="SOC Reports" desc="Live global threat distribution maps." />
      </div>
    </motion.div>
  );
}

function FeatureCard({ icon, title, desc }) {
  return (
    <div className="p-8 rounded-3xl bg-slate-900/40 border border-white/5 hover:border-emerald-500/20 transition-all text-center">
      <div className="mx-auto w-12 h-12 bg-emerald-500/10 rounded-2xl flex items-center justify-center text-emerald-500 mb-6 border border-emerald-500/10">
        {icon}
      </div>
      <h3 className="text-lg font-bold mb-2">{title}</h3>
      <p className="text-sm text-slate-500">{desc}</p>
    </div>
  );
}

// ── USER PORTAL VIEW (SCANNER) ────────────────────────────────────────────────
function PortalView({ setView, news }) {
  const [activeTab, setActiveTab] = useState('SCAN');
  const [inputText, setInputText] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const fileInputRef = useRef(null);

  const handleTextScan = async () => {
    if (!inputText.trim()) return;
    setScanning(true);
    setScanResult(null);
    try {
      const res = await fetch('http://localhost:3000/api/scan/text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: inputText })
      });
      setScanResult(await res.json());
    } catch (e) { console.error(e); }
    finally { setScanning(false); }
  };

  const handleFileScan = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setScanning(true);
    setScanResult(null);
    const formData = new FormData();
    formData.append('file', file);
    try {
      const res = await fetch('http://localhost:3000/api/scan/file', {
        method: 'POST',
        body: formData
      });
      setScanResult(await res.json());
    } catch (e) { console.error(e); }
    finally { setScanning(false); }
  };

  return (
    <motion.div initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} className="max-w-7xl mx-auto px-6 pb-20">
      <div className="flex flex-col md:flex-row gap-8">
        {/* Portal Nav */}
        <div className="w-full md:w-64 space-y-2">
          <TabButton active={activeTab === 'SCAN'} icon={<Search />} label="AI Scanner" onClick={() => setActiveTab('SCAN')} />
          <TabButton active={activeTab === 'NEWS'} icon={<Newspaper />} label="Security News" onClick={() => setActiveTab('NEWS')} />
          <TabButton active={activeTab === 'HELP'} icon={<PhoneCall />} label="Helplines" onClick={() => setActiveTab('HELP')} />
        </div>

        {/* Portal Content */}
        <div className="flex-1">
          <AnimatePresence mode="wait">
            {activeTab === 'SCAN' && (
              <motion.div key="scan" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }}>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                  <div className="p-8 rounded-3xl bg-slate-900/40 border border-white/5 backdrop-blur-xl">
                    <h3 className="text-xl font-bold mb-6 flex items-center gap-3">
                      <div className="p-2 bg-blue-500/10 rounded-lg"><FileText className="h-5 w-5 text-blue-400" /></div>
                      Analyze Message
                    </h3>
                    <textarea
                      value={inputText} onChange={(e) => setInputText(e.target.value)}
                      placeholder="Paste a suspicious SMS, email, or link here..."
                      className="w-full h-48 bg-black/40 border border-white/10 rounded-2xl p-4 text-slate-300 focus:border-emerald-500/50 outline-none transition-all mb-4 resize-none"
                    />
                    <button
                      disabled={scanning} onClick={handleTextScan}
                      className="w-full py-4 bg-emerald-600 hover:bg-emerald-500 rounded-2xl font-black text-sm tracking-widest flex items-center justify-center gap-3 transition-all disabled:opacity-50"
                    >
                      {scanning ? <RefreshCw className="h-5 w-5 animate-spin" /> : <Search className="h-5 w-5" />}
                      {scanning ? "INITIALIZING_AGENTS..." : "RUN AI SCAN"}
                    </button>
                  </div>

                  <div className="p-8 rounded-3xl bg-slate-900/40 border border-white/5 backdrop-blur-xl">
                    <h3 className="text-xl font-bold mb-6 flex items-center gap-3">
                      <div className="p-2 bg-purple-500/10 rounded-lg"><Upload className="h-5 w-5 text-purple-400" /></div>
                      Analyze File
                    </h3>
                    <div
                      onClick={() => fileInputRef.current.click()}
                      className="w-full h-48 border-2 border-dashed border-white/10 rounded-2xl flex flex-col items-center justify-center gap-3 cursor-pointer hover:border-emerald-500/30 hover:bg-emerald-500/5 transition-all group mb-4"
                    >
                      <input type="file" ref={fileInputRef} onChange={handleFileScan} className="hidden" />
                      <Upload className="h-10 w-10 text-slate-600 group-hover:text-emerald-500 group-hover:scale-110 transition-all" />
                      <span className="text-slate-500 font-bold text-xs tracking-widest uppercase">DROP_SUSPECT_FILE_HERE</span>
                    </div>
                    <div className="flex items-center gap-2 text-[10px] text-slate-600 font-bold uppercase tracking-wider px-2">
                      <Info className="h-3 w-3" /> Binary signature & manifest verification
                    </div>
                  </div>
                </div>

                {scanning && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-8 p-12 bg-black/40 border border-white/5 rounded-3xl flex flex-col items-center text-center">
                    <div className="w-16 h-16 border-4 border-emerald-500 border-t-transparent rounded-full animate-spin mb-6" />
                    <div className="space-y-2">
                      <LoadingStep text="[1/3] INTERCEPTING_PAYLOAD..." delay={0} />
                      <LoadingStep text="[2/3] RUNNING_MULTI_AGENT_ANALYSIS..." delay={1} />
                      <LoadingStep text="[3/3] GENERATING_SECURITY_VERDICT..." delay={2} />
                    </div>
                  </motion.div>
                )}

                {scanResult && !scanning && (
                  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className={`mt-8 p-10 rounded-[3rem] border-2 relative overflow-hidden ${scanResult.severity === 'CRITICAL' || scanResult.severity === 'HIGH' ? 'bg-red-500/5 border-red-500/20' : 'bg-emerald-500/5 border-emerald-500/20'}`}>
                    <div className={`absolute top-0 right-0 p-8 opacity-10 ${scanResult.severity === 'CRITICAL' || scanResult.severity === 'HIGH' ? 'text-red-500' : 'text-emerald-500'}`}>
                      <ShieldAlert className="h-32 w-32" />
                    </div>

                    <div className="relative z-10">
                      <div className="flex items-center gap-3 mb-6">
                        <div className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-[0.2em] border ${scanResult.severity === 'CRITICAL' || scanResult.severity === 'HIGH' ? 'bg-red-500/10 text-red-400 border-red-500/20' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'}`}>
                          Agent Intelligence Report
                        </div>
                        <div className="h-px flex-1 bg-white/5" />
                      </div>

                      <div className="flex flex-col md:flex-row md:items-center gap-8">
                        <div className={`w-20 h-20 rounded-3xl flex items-center justify-center shadow-2xl ${scanResult.severity === 'CRITICAL' || scanResult.severity === 'HIGH' ? 'bg-red-500 shadow-red-500/20' : 'bg-emerald-500 shadow-emerald-500/20'}`}>
                          {scanResult.severity === 'CRITICAL' ? <ShieldAlert className="h-10 w-10 text-white" /> : <ShieldCheck className="h-10 w-10 text-white" />}
                        </div>

                        <div className="flex-1">
                          <div className="flex items-center gap-4 mb-2">
                            <h4 className="text-3xl font-black tracking-tighter text-white">{scanResult.threat_type}</h4>
                            <SeverityBadge severity={scanResult.severity} />
                          </div>
                          <div className="p-6 bg-black/40 rounded-2xl border border-white/5 font-medium text-slate-300 leading-relaxed italic">
                            "{scanResult.message}"
                          </div>
                        </div>
                      </div>

                      <div className="mt-8 pt-8 border-t border-white/5 grid grid-cols-2 md:grid-cols-4 gap-4">
                        <ResultInfo label="SCAN_ID" value={`#${Math.floor(Math.random() * 9000) + 1000}`} />
                        <ResultInfo label="TIMESTAMP" value={new Date().toLocaleTimeString()} />
                        <ResultInfo label="AI_CONFIDENCE" value="98.4%" />
                        <ResultInfo label="STATUS" value="ACTION_TAKEN" />
                      </div>
                    </div>
                  </motion.div>
                )}
              </motion.div>
            )}

            {activeTab === 'NEWS' && (
              <motion.div key="news" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {news.map((item, i) => (
                  <div key={item.id} className="p-8 rounded-3xl bg-slate-900/40 border border-white/5 group hover:border-emerald-500/20 transition-all">
                    <div className="text-[10px] font-black text-emerald-500 mb-4 uppercase tracking-[0.2em]">{item.category}</div>
                    <h3 className="text-lg font-bold mb-4 group-hover:text-white">{item.title}</h3>
                    <p className="text-sm text-slate-500 mb-6 leading-relaxed">{item.summary}</p>
                    <div className="flex justify-between items-center text-[10px] font-mono text-slate-600 pt-4 border-t border-white/5">
                      <span>{item.date}</span>
                      <SeverityBadge severity={item.severity} />
                    </div>
                  </div>
                ))}
              </motion.div>
            )}

            {activeTab === 'HELP' && (
              <motion.div key="help" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <HelplineCard number="1930" label="National Cybercrime" color="red" />
                <HelplineCard number="112" label="All-Emergency" color="blue" />
                <HelplineCard number="1091" label="Women Helpline" color="emerald" />
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </motion.div>
  );
}

function TabButton({ active, icon, label, onClick }) {
  return (
    <button
      onClick={onClick}
      className={`w-full flex items-center gap-4 p-4 rounded-2xl transition-all font-black text-xs tracking-widest uppercase ${active ? 'bg-emerald-600 text-white shadow-[0_0_15px_rgba(16,185,129,0.2)]' : 'text-slate-500 hover:bg-white/5'}`}
    >
      {icon} {label}
    </button>
  );
}


// ── ADMIN VIEW (EXISTING SOC) ───────────────────────────────────────────────
function AdminView({ setView, stats, recentLogs }) {
  const currentHour = new Date().getHours();
  const heatmapData = stats?.hourly_heatmap || Array.from({ length: 24 }, (_, i) => ({ hour: i, count: 0 }));
  const [activeAlert, setActiveAlert] = useState(null);

  // Detect new logs for real-time pulse
  useEffect(() => {
    if (recentLogs.length > 0) {
      const latest = recentLogs[0];
      const logTime = new Date(latest.timestamp).getTime();
      const now = new Date().getTime();
      // If log is from last 10 seconds, trigger pulse
      if (now - logTime < 10000) {
        setActiveAlert(latest);
        const timer = setTimeout(() => setActiveAlert(null), 5000);
        return () => clearTimeout(timer);
      }
    }
  }, [recentLogs]);

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="max-w-[1600px] mx-auto px-6 pb-20">
      {/* Real-time Status Bar - Command Center Style */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-10 p-6 bg-slate-900/80 border border-emerald-500/30 rounded-3xl backdrop-blur-3xl shadow-[0_20px_50px_rgba(0,0,0,0.5)]">
        <div className="flex items-center gap-6 mb-4 md:mb-0">
          <div className="relative">
            <div className="w-12 h-12 rounded-2xl bg-emerald-500/20 flex items-center justify-center border border-emerald-500/40">
              <Activity className="h-6 w-6 text-emerald-500 animate-pulse" />
            </div>
            <div className="absolute -top-1 -right-1 w-3 h-3 bg-emerald-500 rounded-full border-2 border-slate-900" />
          </div>
          <div>
            <h2 className="text-2xl font-black tracking-tighter text-white leading-none mb-1">SOC_COMMAND_CENTER</h2>
            <div className="flex items-center gap-3">
              <span className="text-[10px] font-mono text-emerald-500 uppercase tracking-widest font-bold">Protocol: active_defense</span>
              <span className="h-1 w-1 rounded-full bg-slate-700" />
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">Version: 2.4.0_Stable</span>
            </div>
          </div>
        </div>
        
        <div className="flex flex-wrap gap-4">
          <div className="px-4 py-2 bg-black/40 rounded-xl border border-white/5 flex flex-col items-end">
            <span className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Global_Latency</span>
            <span className="text-sm font-mono text-blue-400">0.42ms</span>
          </div>
          <div className="px-4 py-2 bg-black/40 rounded-xl border border-white/5 flex flex-col items-end">
            <span className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Active_Nodes</span>
            <span className="text-sm font-mono text-white">1,024_Online</span>
          </div>
          <div className="px-4 py-2 bg-emerald-500/10 rounded-xl border border-emerald-500/20 flex flex-col items-end">
            <span className="text-[9px] text-emerald-500/60 font-bold uppercase tracking-widest">System_Health</span>
            <span className="text-sm font-mono text-emerald-500 font-black">99.9%</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
        <StatCard title="Total Interceptions" value={stats?.total_scans || 0} icon={<Search className="h-5 w-5" />} color="emerald" desc="Live scans processed" />
        <StatCard title="Critical Blocks" value={stats?.critical_count || 0} icon={<ShieldAlert className="h-5 w-5" />} color="red" desc="High-risk threats stopped" />
        <StatCard title="Phishing Vectors" value={stats?.high_count || 0} icon={<AlertTriangle className="h-5 w-5" />} color="orange" desc="Active phishing campaign nodes" />
        <StatCard title="Shielded Assets" value={stats?.active_users || 0} icon={<Users className="h-5 w-5" />} color="blue" desc="Individual accounts protected" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 mb-12">
        {/* LIVE THREAT MAP */}
        <div className="lg:col-span-8 p-10 rounded-[2.5rem] bg-slate-900/40 border border-white/5 backdrop-blur-2xl relative overflow-hidden group shadow-2xl">
          <div className="absolute top-0 right-0 p-10 flex items-center gap-4">
             <div className="flex items-center gap-2 px-4 py-2 bg-black/40 border border-white/10 rounded-2xl">
               <span className="text-[10px] font-mono text-slate-500">Live_Traffic_Monitor</span>
               <div className="flex gap-1">
                 <div className="w-1 h-3 bg-emerald-500/50 animate-pulse" />
                 <div className="w-1 h-4 bg-emerald-500 animate-pulse" style={{ animationDelay: '0.2s' }} />
                 <div className="w-1 h-2 bg-emerald-500/30 animate-pulse" style={{ animationDelay: '0.4s' }} />
               </div>
             </div>
          </div>

          <div className="mb-10">
            <h2 className="text-3xl font-black mb-2 flex items-center gap-3 text-white tracking-tighter">
              <Globe className="text-emerald-500 h-8 w-8" /> THREAT_GEOGRAPHY
            </h2>
            <p className="text-xs text-slate-500 font-mono uppercase tracking-[0.3em]">India Regional Intelligence Grid</p>
          </div>

          <div className="flex flex-col lg:flex-row items-center gap-16">
            <div className="relative scale-110 lg:scale-125 origin-center">
              {/* Scan Circle Decorative */}
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[300px] h-[300px] border border-emerald-500/10 rounded-full animate-[spin_10s_linear_infinite]" />
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[400px] h-[400px] border border-emerald-500/5 rounded-full animate-[spin_20s_linear_infinite_reverse]" />
              
              {/* Live Tracking Path Effect */}
              {activeAlert && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.5 }}
                  animate={{ opacity: [0, 1, 0], scale: [0.5, 1.5, 0.5] }}
                  transition={{ duration: 1.5, repeat: Infinity }}
                  className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-64 h-64 border-2 border-red-500/30 rounded-full z-0"
                />
              )}

              <IndiaThreatMap activeRegion={activeAlert?.region} />
            </div>

            <div className="flex-1 w-full space-y-6 z-10">
              <div className="flex items-center justify-between border-b border-white/5 pb-4">
                <h3 className="text-[10px] font-black text-white uppercase tracking-[0.2em]">Regional_Threat_Index</h3>
                <RefreshCw className="h-3 w-3 text-slate-600 animate-spin" />
              </div>
              
              <div className="space-y-4">
                {stats?.state_data?.slice(0, 5).map((state, i) => (
                  <motion.div 
                    initial={{ x: 20, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    transition={{ delay: i * 0.1 }}
                    key={i} 
                    className="p-4 bg-black/30 rounded-2xl border border-white/5 hover:border-emerald-500/30 transition-all group"
                  >
                    <div className="flex justify-between items-center mb-3">
                      <span className="text-xs font-black text-white tracking-widest uppercase">{state.name}</span>
                      <span className="text-[10px] font-mono text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded-md">{state.value} Hits</span>
                    </div>
                    <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                      <motion.div 
                        initial={{ width: 0 }}
                        animate={{ width: `${(state.value / (stats.total_scans || 1)) * 100}%` }}
                        className="h-full bg-gradient-to-r from-emerald-600 to-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.5)]" 
                      />
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          </div>

          <AnimatePresence>
            {activeAlert && (
              <motion.div
                initial={{ y: 50, opacity: 0, scale: 0.9 }} animate={{ y: 0, opacity: 1, scale: 1 }} exit={{ y: 50, opacity: 0, scale: 0.9 }}
                className="absolute bottom-8 right-8 left-8 p-6 bg-red-600 border border-red-400/50 rounded-3xl shadow-[0_0_100px_rgba(239,68,68,0.4)] z-50 flex items-center gap-6 backdrop-blur-xl"
              >
                <div className="w-16 h-16 bg-white/10 rounded-2xl flex items-center justify-center animate-pulse border border-white/20">
                  <ShieldAlert className="h-10 w-10 text-white" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-1">
                    <span className="px-2 py-0.5 bg-black/20 rounded text-[9px] font-black text-white uppercase tracking-widest">LIVE_INTERCEPTION</span>
                    <span className="text-[10px] font-mono text-white/70">TARGET: {activeAlert.region}</span>
                  </div>
                  <h4 className="text-xl font-black text-white tracking-tight mb-2">{activeAlert.threat_type} Identified</h4>
                  <p className="text-sm text-white/80 font-medium leading-tight">"{activeAlert.message.substring(0, 100)}..."</p>
                </div>
                <button className="px-6 py-3 bg-black text-white rounded-xl text-xs font-black tracking-widest uppercase hover:bg-slate-800 transition-all border border-white/10">Counter_Active</button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* THREAT VECTOR PIE */}
        <div className="lg:col-span-4 p-10 rounded-[2.5rem] bg-slate-900/40 border border-white/5 backdrop-blur-2xl flex flex-col shadow-2xl relative">
          <div className="mb-10">
            <h2 className="text-lg font-black mb-1 flex items-center gap-2 text-white">
              <Activity className="text-emerald-500" /> ANALYSIS_VECTORS
            </h2>
            <p className="text-[10px] text-slate-500 font-mono tracking-widest">Threat Category Distribution</p>
          </div>
          
          <div className="h-64 mb-10 relative">
             {/* Decorative Background for Chart */}
             <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <div className="w-32 h-32 bg-emerald-500/5 blur-2xl rounded-full" />
             </div>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={stats?.threat_types || [{ name: 'Idle', value: 1 }]} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={70} outerRadius={95} paddingAngle={8} stroke="none">
                  {stats?.threat_types?.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} className="hover:opacity-80 transition-opacity cursor-pointer" />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '16px', fontSize: '10px', boxShadow: '0 10px 30px rgba(0,0,0,0.5)' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="space-y-3 mt-auto">
            {stats?.threat_types?.map((type, i) => (
              <div key={i} className="flex justify-between items-center text-[10px] font-black uppercase tracking-[0.2em] text-slate-400 p-4 bg-black/30 rounded-2xl border border-white/5 hover:border-white/10 transition-all">
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[i % COLORS.length] }} />
                  <span>{type.name}</span>
                </div>
                <span className="text-white bg-white/5 px-2 py-1 rounded-md">{type.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* LIVE TELEMETRY STREAM */}
      <div className="p-10 rounded-[2.5rem] bg-black border border-emerald-500/20 shadow-[0_0_50px_rgba(16,185,129,0.05)] relative overflow-hidden">
        <div className="flex justify-between items-center mb-8 border-b border-white/5 pb-6">
           <div>
             <h2 className="text-xl font-black text-white flex items-center gap-3">
               <Terminal className="text-emerald-500" /> LIVE_TELEMETRY_STREAM
             </h2>
             <p className="text-[10px] text-slate-500 font-mono tracking-widest mt-1 uppercase">Encrypted Packet Monitoring active</p>
           </div>
           <div className="flex gap-4">
              <div className="px-3 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-[9px] font-black text-emerald-500 uppercase tracking-widest animate-pulse">Streaming_Live</div>
              <div className="flex gap-1.5 items-center">
                <div className="w-2 h-2 rounded-full bg-red-500/50" />
                <div className="w-2 h-2 rounded-full bg-yellow-500/50" />
                <div className="w-2 h-2 rounded-full bg-emerald-500" />
              </div>
           </div>
        </div>

        <div className="h-[400px] overflow-y-auto space-y-3 pt-2 scrollbar-hide pr-4">
          {recentLogs.map((log, i) => (
            <motion.div 
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.05 }}
              key={i} 
              className="font-mono text-[11px] p-4 bg-white/[0.02] border border-white/5 rounded-xl flex flex-col md:flex-row md:items-center gap-4 hover:bg-white/[0.05] transition-all group border-l-4"
              style={{ borderLeftColor: log.severity === 'CRITICAL' ? '#ef4444' : log.severity === 'HIGH' ? '#f59e0b' : '#10b981' }}
            >
              <div className="flex items-center gap-4 min-w-[300px]">
                <span className="text-slate-500 font-bold">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                <span className="text-blue-500 font-black tracking-tighter">{log.user_id === 'WebUser' ? 'SRC:WEB_PORTAL' : log.user_id === 'Demo_Simulator' ? 'SRC:DEMO_LAB' : 'SRC:TG_BOT'}</span>
              </div>
              <div className="flex-1">
                <span className={`font-black uppercase tracking-widest px-2 py-0.5 rounded ${log.severity === 'CRITICAL' ? 'text-red-500 bg-red-500/10' : log.severity === 'HIGH' ? 'text-orange-500 bg-orange-500/10' : 'text-emerald-500 bg-emerald-500/10'}`}>
                  {log.threat_type}
                </span>
                <span className="text-slate-400 mx-3 font-medium">at</span>
                <span className="text-white font-black">{log.region}</span>
                <span className="text-slate-600 ml-4 italic opacity-60 group-hover:opacity-100 transition-opacity">Payload: "{log.message.substring(0, 40)}..."</span>
              </div>
              <div className="text-[9px] font-black text-emerald-500 bg-emerald-500/10 px-2 py-1 rounded uppercase tracking-[0.1em]">Status: intercepted</div>
            </motion.div>
          ))}
          {recentLogs.length === 0 && (
            <div className="flex flex-col items-center justify-center py-20 text-slate-700">
              <RefreshCw className="h-8 w-8 mb-4 animate-spin opacity-20" />
              <div className="font-mono text-sm tracking-[0.5em] animate-pulse">AWAITING_TELEMETRY_PACKETS...</div>
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
}

// ── LIVE DEMO VIEW ──────────────────────────────────────────────────────────
const SCENARIOS = [
  {
    id: 'whatsapp',
    title: 'WhatsApp Job Scam',
    app: 'WhatsApp',
    color: '#25D366',
    sender: 'Amazon HR (Sarah)',
    message: 'Congratulations! Your profile is selected for a Part-Time job. Like 3 YouTube videos and earn ₹500/task. DM for details.',
    threat: {
      severity: 'HIGH',
      type: 'Task-Based Fraud',
      verdict: 'This is a "Like & Earn" scam. They will pay small amounts initially to gain trust, then ask for huge "Investments".'
    }
  },
  {
    id: 'instagram',
    title: 'Instagram Copyright DM',
    app: 'Instagram',
    color: '#E1306C',
    sender: 'Meta Support Center',
    message: 'Notice: Your recent post violates our Copyright Guidelines. Your account will be deleted in 24 hours. Appeal here: bit.ly/ig-copyright-appeal',
    threat: {
      severity: 'CRITICAL',
      type: 'Credential Phishing',
      verdict: 'Meta NEVER sends copyright notices via DM. This link will steal your login password and 2FA code.'
    }
  },
  {
    id: 'facebook',
    title: 'FB Security Alert',
    app: 'Facebook',
    color: '#1877F2',
    sender: 'Security_Team_Alert',
    message: 'Urgent: Unusual login detected from Moscow, Russia. If this was not you, please secure your account immediately at: facebook-security-fix.co',
    threat: {
      severity: 'HIGH',
      type: 'Account Takeover',
      verdict: 'Fake security alerts are used to create panic. The link leads to a phishing page designed to bypass your security.'
    }
  },
  {
    id: 'upi',
    title: 'UPI Payment Request',
    app: 'Google Pay',
    color: '#4285F4',
    sender: 'SBI_Refund_Portal',
    message: 'Payment Request: ₹15,000. Note: "Verify your UPI PIN to receive the Income Tax Refund of ₹15,000 directly to your bank."',
    threat: {
      severity: 'CRITICAL',
      type: 'Payment Fraud',
      verdict: 'CRITICAL: You NEVER need to enter your UPI PIN to RECEIVE money. Entering your PIN will DEBIT ₹15,000 from your account.'
    }
  },
  {
    id: 'phonepe',
    title: 'PhonePe Cashback Scam',
    app: 'PhonePe',
    color: '#5f259f',
    sender: 'PhonePe_Rewards',
    message: 'Congratulations! You won a scratch card of ₹2,500. Click here to claim your cashback instantly in your bank account: claim-phonepe-reward.in',
    threat: {
      severity: 'HIGH',
      type: 'Reward Fraud',
      verdict: 'Genuine rewards never require clicking suspicious third-party links or entering PINs. This is a trap to drain your wallet.'
    }
  },
  {
    id: 'paytm',
    title: 'Paytm KYC Update',
    app: 'Paytm',
    color: '#00baf2',
    sender: 'Paytm_KYC_Center',
    message: 'Your Paytm Wallet will be suspended today due to pending KYC. To avoid suspension, call 9123456789 and install the "AnyDesk" app for remote assistance.',
    threat: {
      severity: 'CRITICAL',
      type: 'Remote Access Scam',
      verdict: 'CRITICAL: Never install remote access apps like AnyDesk or TeamViewer on a stranger\'s request. They will take full control of your phone.'
    }
  },
  {
    id: 'sms',
    title: 'Banking SMS Phishing',
    app: 'Messages',
    color: '#6366f1',
    sender: '+91 91234 56789',
    message: 'Dear Customer, your SBI YONO account will be deactivated today. Please update your KYC by clicking here: sbi-kyc-update.live',
    threat: {
      severity: 'CRITICAL',
      type: 'Netbanking Fraud',
      verdict: 'The link leads to a malicious site that captures your username, password, and OTP. Banks never send such links.'
    }
  }
];

function DemoView() {
  const [activeScenario, setActiveScenario] = useState(null);
  const [status, setStatus] = useState('IDLE'); // IDLE, RECEIVING, SCANNING, INTERCEPTED
  const [messages, setMessages] = useState([]);

  const runSimulation = (scenario) => {
    setActiveScenario(scenario);
    setStatus('RECEIVING');
    setMessages([]);
    
    // Step 1: Message arrives
    setTimeout(() => {
      setMessages([{ text: scenario.message, type: 'received' }]);
      setStatus('SCANNING');
      
      // Step 2: Agent Intercepts
      setTimeout(() => {
        setStatus('INTERCEPTED');
        // Report to Backend SOC
        fetch('http://localhost:3000/api/logs', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            user_id: 'Demo_Simulator',
            message: scenario.message,
            threat_type: scenario.threat.type,
            severity: scenario.threat.severity,
            language: 'EN'
          })
        }).catch(err => console.error("Demo reporting failed:", err));
      }, 1500);
    }, 1000);
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="max-w-7xl mx-auto px-6 pb-20">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
        
        {/* Scenario Selection */}
        <div className="space-y-8">
          <div>
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[10px] font-black tracking-widest mb-6 uppercase">
              <Smartphone className="h-4 w-4" /> Interactive Simulation
            </div>
            <h2 className="text-6xl font-black tracking-tighter mb-4">LIVE_DEMO</h2>
            <p className="text-slate-500 max-w-md text-sm">Experience how our Agentic AI monitors mobile traffic and intercepts threats before they can cause harm.</p>
          </div>

          <div className="space-y-4">
            {SCENARIOS.map(s => (
              <button
                key={s.id}
                onClick={() => runSimulation(s)}
                disabled={status === 'RECEIVING'}
                className={`w-full p-6 rounded-3xl border text-left transition-all group flex items-center justify-between ${activeScenario?.id === s.id ? 'bg-emerald-500/10 border-emerald-500/50 shadow-[0_0_30px_rgba(16,185,129,0.1)]' : 'bg-white/5 border-white/5 hover:border-white/20'}`}
              >
                <div>
                  <h4 className="font-bold text-white mb-1">{s.title}</h4>
                  <p className="text-[10px] text-slate-500 font-mono uppercase tracking-widest">{s.app} • Simulation</p>
                </div>
                <div className={`p-3 rounded-2xl transition-all ${activeScenario?.id === s.id ? 'bg-emerald-500 text-white' : 'bg-white/5 text-slate-500 group-hover:scale-110'}`}>
                  <ArrowRight className="h-5 w-5" />
                </div>
              </button>
            ))}
          </div>

          <div className="p-6 rounded-3xl bg-blue-500/5 border border-blue-500/10 flex gap-4">
            <div className="p-3 bg-blue-500/10 rounded-xl h-fit"><Info className="h-5 w-5 text-blue-400" /></div>
            <p className="text-xs text-slate-400 leading-relaxed">
              When a threat is intercepted, it is automatically reported to the <b>Admin SOC</b>. 
              Open the Admin Dashboard in another tab to see the live telemetry stream.
            </p>
          </div>
        </div>

        {/* Phone Simulator UI */}
        <div className="flex justify-center relative">
          {/* Decorative background glow */}
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[120%] h-[120%] bg-emerald-500/5 blur-[120px] rounded-full pointer-events-none" />
          
          <div className="phone-simulator">
            <div className="phone-notch" />
              <div className="phone-screen">
                {/* Phone Header */}
                <div className="phone-status-bar">
                  <span>9:41</span>
                  <div className="flex gap-1.5">
                    <div className="w-3 h-2 bg-white/20 rounded-sm" />
                    <div className="w-3 h-2 bg-white/60 rounded-sm" />
                  </div>
                </div>

                {/* App Header */}
                <div className="px-6 py-4 border-b border-white/5 flex items-center gap-3 bg-black/20">
                  <div className="w-10 h-10 rounded-full flex items-center justify-center text-white relative shadow-lg" style={{ backgroundColor: activeScenario?.color || '#334155' }}>
                    {activeScenario?.app === 'Instagram' && <Globe size={20} />}
                    {activeScenario?.app === 'Facebook' && <Users size={20} />}
                    {activeScenario?.app === 'WhatsApp' && <MessageSquare size={20} />}
                    {activeScenario?.app === 'Google Pay' && <ShieldCheck size={20} />}
                    {activeScenario?.app === 'PhonePe' && <ShieldAlert size={20} />}
                    {activeScenario?.app === 'Paytm' && <LayoutDashboard size={20} />}
                    {activeScenario?.app === 'Messages' && <MessageSquare size={20} />}
                    {!activeScenario && <Smartphone size={20} />}
                    
                    {status === 'SCANNING' && (
                      <motion.div 
                        initial={{ scale: 0.8, opacity: 0 }}
                        animate={{ scale: 1.2, opacity: 1 }}
                        className="absolute -top-1 -right-1 w-4 h-4 bg-emerald-500 rounded-full border-2 border-black flex items-center justify-center"
                      >
                        <RefreshCw size={8} className="animate-spin text-white" />
                      </motion.div>
                    )}
                  </div>
                  <div className="flex-1">
                    <div className="text-[12px] font-black text-white">{activeScenario?.sender || "Mobile Device"}</div>
                    <div className="text-[9px] text-slate-500 flex items-center gap-1 font-bold uppercase tracking-wider">
                      {status === 'SCANNING' ? (
                        <span className="text-emerald-500 animate-pulse">Agent_Scanning...</span>
                      ) : (
                        <span>{activeScenario?.app || "Ready"} • Secure</span>
                      )}
                    </div>
                  </div>
                </div>

              {/* Chat Content */}
              <div className="phone-content scrollbar-hide">
                <AnimatePresence>
                  {messages.map((m, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, y: 10, scale: 0.9 }}
                      animate={{ opacity: 1, y: 0, scale: 1 }}
                      className={`message-bubble ${m.type === 'sent' ? 'message-sent' : 'message-received'}`}
                    >
                      {m.text}
                    </motion.div>
                  ))}
                </AnimatePresence>
              </div>

              {/* Agent Alert Overlay */}
              <AnimatePresence>
                {status === 'INTERCEPTED' && activeScenario && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.9, y: 20 }}
                    animate={{ opacity: 1, scale: 1, y: 0 }}
                    exit={{ opacity: 0, scale: 0.9, y: 20 }}
                    className="agent-overlay"
                  >
                    <div className="agent-shield-glow mb-6">
                      <div className="p-5 bg-emerald-500 rounded-full animate-pulse-emerald">
                        <ShieldCheck className="h-10 w-10 text-white" />
                      </div>
                    </div>
                    
                    <div className="bg-slate-900 border border-emerald-500/30 p-6 rounded-[2rem] w-full shadow-2xl">
                      <div className="text-[8px] font-black text-emerald-500 uppercase tracking-[0.2em] mb-2">Agentic Guard Intercept</div>
                      <h3 className="text-lg font-black text-white mb-2 leading-tight">{activeScenario.threat.type} Detected</h3>
                      <p className="text-[10px] text-slate-400 mb-6 leading-relaxed italic">
                        "{activeScenario.threat.verdict}"
                      </p>
                      
                      <button 
                        onClick={() => setStatus('IDLE')}
                        className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 rounded-xl text-[10px] font-black tracking-widest uppercase transition-all"
                      >
                        Secure Dismiss
                      </button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
              
              {/* Fake Input Area */}
              <div className="p-4 border-t border-white/5 bg-slate-900/50 mt-auto flex gap-2">
                <div className="h-8 flex-1 bg-white/5 rounded-full px-4 flex items-center text-[10px] text-slate-500">
                  Message...
                </div>
                <div className="w-8 h-8 rounded-full bg-emerald-600 flex items-center justify-center">
                  <ArrowRight className="h-4 w-4 text-white" />
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

// ── INDIA THREAT MAP COMPONENT ────────────────────────────────────────────────
function IndiaThreatMap({ activeRegion }) {
  // Simplified stylized India shape using hex-grid points
  const points = [
    { id: 'North', x: 50, y: 15, name: 'Delhi', region: 'Delhi' },
    { id: 'North2', x: 45, y: 10, name: 'North', region: 'North' },
    { id: 'West', x: 25, y: 45, name: 'Maharashtra', region: 'Maharashtra' },
    { id: 'Central', x: 50, y: 40, name: 'Central', region: 'Central' },
    { id: 'East', x: 75, y: 45, name: 'East', region: 'East' },
    { id: 'South', x: 45, y: 75, name: 'Karnataka', region: 'Karnataka' },
    { id: 'South2', x: 55, y: 80, name: 'Tamil Nadu', region: 'Tamil Nadu' },
    { id: 'Telangana', x: 52, y: 60, name: 'Telangana', region: 'Telangana' },
    { id: 'UP', x: 58, y: 30, name: 'Uttar Pradesh', region: 'Uttar Pradesh' },
  ];

  return (
    <div className="relative w-64 h-80 bg-black/20 rounded-3xl p-4 flex items-center justify-center border border-white/5">
      <svg viewBox="0 0 100 100" className="w-full h-full">
        {/* Simple Outline Connection */}
        <path
          d="M50,5 L70,15 L85,45 L70,70 L50,95 L30,70 L15,45 L30,15 Z"
          fill="none" stroke="rgba(16,185,129,0.05)" strokeWidth="0.5"
        />

        {points.map((p) => {
          const isActive = activeRegion === p.region;
          return (
            <g key={p.id}>
              {/* Background Glow */}
              <motion.circle
                cx={p.x} cy={p.y} r={isActive ? 8 : 2}
                fill={isActive ? "rgba(239, 68, 68, 0.4)" : "rgba(16, 185, 129, 0.2)"}
                animate={isActive ? { scale: [1, 2, 1], opacity: [0.3, 0.6, 0.3] } : {}}
                transition={{ repeat: Infinity, duration: 2 }}
              />
              {/* Core Point */}
              <circle
                cx={p.x} cy={p.y} r="1.5"
                fill={isActive ? "#ef4444" : "#10b981"}
                className="transition-colors duration-500"
              />
              {/* Pulse Ring */}
              {isActive && (
                <motion.circle
                  cx={p.x} cy={p.y} r="1.5"
                  fill="none" stroke="#ef4444" strokeWidth="0.5"
                  initial={{ scale: 1, opacity: 1 }}
                  animate={{ scale: 5, opacity: 0 }}
                  transition={{ repeat: Infinity, duration: 1.5 }}
                />
              )}
              {/* Label */}
              <text
                x={p.x + 3} y={p.y + 1}
                fontSize="3" fill={isActive ? "#fff" : "#475569"}
                className="font-mono font-bold pointer-events-none transition-colors"
              >
                {p.name}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// ── CYBER EMERGENCY VIEW ──────────────────────────────────────────────────
function HelpView() {
  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="max-w-7xl mx-auto px-6 pb-20">
      <div className="text-center mb-16">
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-[10px] font-black tracking-widest mb-6 uppercase">
          <ShieldAlert className="h-4 w-4" /> 24/7 Incident Response Active
        </div>
        <h2 className="text-6xl font-black tracking-tighter mb-4">EMERGENCY_DESK</h2>
        <p className="text-slate-500 max-w-xl mx-auto text-sm">If you have been scammed, every second counts. Follow the steps below and contact authorities immediately.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-20">
        <HelplineCard number="1930" label="National Cybercrime Hotline" color="red" />
        <HelplineCard number="112" label="Immediate Local Police Assistance" color="blue" />
        <HelplineCard number="1091" label="Women Safety & Cyber Stalking" color="emerald" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-start">
        <div className="p-10 rounded-[3rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl">
          <h3 className="text-2xl font-black mb-8 flex items-center gap-3">
            <Activity className="text-red-500" /> VICTIM_FIRST_AID
          </h3>
          <div className="space-y-6">
            <Step item="01" title="Freeze Accounts" desc="Call your bank immediately or use their app to block all cards and net banking." />
            <Step item="02" title="Preserve Evidence" desc="Take screenshots of all chat history, transaction IDs, and fraudulent links." />
            <Step item="03" title="Report on 1930" desc="Call 1930 or visit cybercrime.gov.in within the 'Golden Hour' (first 2 hours)." />
            <Step item="04" title="Reset Passwords" desc="Change passwords for your email and social media from a different secure device." />
          </div>
        </div>

        <div className="space-y-8">
          <div className="p-10 rounded-[3rem] bg-emerald-500/10 border border-emerald-500/20 backdrop-blur-xl relative overflow-hidden">
            <div className="absolute top-[-20%] right-[-10%] w-64 h-64 bg-emerald-500/10 rounded-full blur-3xl" />
            <h3 className="text-2xl font-black mb-4 flex items-center gap-3">
              <Cpu className="text-emerald-500" /> AGENT_ADVICE
            </h3>
            <p className="text-slate-300 text-sm leading-relaxed mb-6">
              "Our AI Agent recommends never clicking links that promise 'tax refunds' or 'lottery wins'.
              No government agency will ever ask for your OTP or conduct a 'Digital Arrest' via WhatsApp video call.
              Stay calm, stay secure."
            </p>
            <div className="flex items-center gap-4 p-4 bg-black/40 rounded-2xl border border-white/5">
              <div className="p-2 bg-emerald-500 rounded-lg"><Fingerprint className="h-4 w-4 text-white" /></div>
              <span className="text-[10px] font-mono text-emerald-500 uppercase tracking-widest font-bold">Encrypted Guidance Stream</span>
            </div>
          </div>

          <div className="p-8 rounded-[3rem] bg-white/5 border border-white/10 text-center">
            <h4 className="font-bold text-white mb-2">Need a formal report?</h4>
            <p className="text-xs text-slate-500 mb-6">Our system can generate a pre-filled incident report for the police.</p>
            <button className="px-8 py-3 bg-white text-black rounded-xl font-black text-[10px] tracking-widest uppercase hover:bg-slate-200 transition-all">Generate Report PDF</button>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

function Step({ item, title, desc }) {
  return (
    <div className="flex gap-6 group">
      <div className="text-3xl font-black text-white/10 group-hover:text-red-500/20 transition-colors">{item}</div>
      <div>
        <h4 className="font-black text-white text-sm uppercase tracking-widest mb-1">{title}</h4>
        <p className="text-xs text-slate-500 leading-relaxed">{desc}</p>
      </div>
    </div>
  );
}
function StatCard({ title, value, icon, color, desc }) {
  const colors = {
    emerald: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20 shadow-emerald-500/5',
    red: 'text-red-500 bg-red-500/10 border-red-500/20 shadow-red-500/5',
    orange: 'text-orange-500 bg-orange-500/10 border-orange-500/20 shadow-orange-500/5',
    blue: 'text-blue-500 bg-blue-500/10 border-blue-500/20 shadow-blue-500/5'
  };

  return (
    <motion.div 
      whileHover={{ y: -5, scale: 1.02 }}
      className={`p-6 rounded-[2rem] bg-slate-900/40 border border-white/5 backdrop-blur-xl shadow-xl group cursor-pointer hover:border-emerald-500/20 transition-all`}
    >
      <div className="flex justify-between items-start mb-6">
        <div className={`p-3 rounded-2xl ${colors[color]} border group-hover:scale-110 transition-transform`}>
          {icon}
        </div>
        <div className="flex gap-1">
          <div className="w-1 h-1 rounded-full bg-slate-700" />
          <div className="w-1 h-1 rounded-full bg-slate-700" />
          <div className="w-1 h-1 rounded-full bg-slate-700" />
        </div>
      </div>
      <div className="space-y-1">
        <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">{title}</h3>
        <div className="flex items-baseline gap-2">
           <span className="text-3xl font-black text-white tracking-tighter">{value}</span>
           <span className="text-[10px] font-mono text-emerald-500/60">+12%</span>
        </div>
        <p className="text-[9px] text-slate-600 font-medium uppercase tracking-widest">{desc}</p>
      </div>
      
      {/* Decorative pulse line at bottom */}
      <div className="mt-6 h-1 w-full bg-white/5 rounded-full overflow-hidden">
        <motion.div 
          animate={{ x: ['-100%', '100%'] }}
          transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
          className="h-full w-1/3 bg-gradient-to-r from-transparent via-emerald-500 to-transparent"
        />
      </div>
    </motion.div>
  );
}

function HelplineCard({ number, label, color }) {
  const colors = {
    red: 'bg-red-500 shadow-red-500/20',
    blue: 'bg-blue-500 shadow-blue-500/20',
    emerald: 'bg-emerald-500 shadow-emerald-500/20'
  };

  return (
    <motion.div 
      whileHover={{ scale: 1.05 }}
      className="p-8 rounded-[2.5rem] bg-slate-900/60 border border-white/5 backdrop-blur-xl text-center group relative overflow-hidden"
    >
      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-white/10 to-transparent" />
      <div className={`mx-auto w-16 h-16 rounded-3xl flex items-center justify-center mb-6 shadow-2xl group-hover:rotate-12 transition-transform ${colors[color]}`}>
        <PhoneCall className="h-8 w-8 text-white" />
      </div>
      <h3 className="text-4xl font-black text-white mb-2 tracking-tighter">{number}</h3>
      <p className="text-xs text-slate-500 font-bold uppercase tracking-widest">{label}</p>
      
      <button className="mt-8 px-6 py-3 bg-white/5 hover:bg-white/10 border border-white/10 text-white rounded-xl text-[10px] font-black tracking-widest uppercase transition-all">
        Call Now
      </button>
    </motion.div>
  );
}

function SeverityBadge({ severity }) {
  const styles = {
    CRITICAL: 'bg-red-500/10 text-red-400 border-red-500/20',
    HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    MEDIUM: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    SAFE: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
  };
  return (
    <span className={`px-2 py-1 rounded-md text-[9px] font-black uppercase tracking-widest border ${styles[severity] || styles.SAFE}`}>
      {severity}
    </span>
  );
}

function ResultInfo({ label, value }) {
  return (
    <div className="flex flex-col">
      <span className="text-[8px] font-black text-slate-500 uppercase tracking-widest mb-1">{label}</span>
      <span className="text-xs font-mono text-white">{value}</span>
    </div>
  );
}
