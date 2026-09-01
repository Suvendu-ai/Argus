import { useState } from 'react'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, BarChart, Bar, Cell
} from 'recharts'
import {
  Shield, Activity, AlertTriangle,
  Eye, Play, Square, FileText, Zap, Wifi, WifiOff
} from 'lucide-react'
import { useArgus } from '../hooks/useArgus'

const SEV_COLOR = {
  CRITICAL : '#ff0044',
  HIGH     : '#ff3c6e',
  MEDIUM   : '#ffa500',
  LOW      : '#00ff88',
}

const ATK_COLOR = {
  DoS          : '#ff3c6e',
  DDoS         : '#ff0044',
  Probe        : '#ffa500',
  PortScan     : '#ffa500',
  R2L          : '#ff6b35',
  U2R          : '#ff0044',
  BruteForce   : '#ff6b35',
  WebAttack    : '#f59e0b',
  Botnet       : '#dc2626',
  Infiltration : '#7c3aed',
  Unknown      : '#a855f7',
}

// ─────────────────────────────────────────
function StatCard({ icon: Icon, label, value, color }) {
  return (
    <div className="stat-card" style={{ borderLeftColor: color }}>
      <div style={{ color }}><Icon size={26} /></div>
      <div>
        <div className="stat-val" style={{ color }}>
          {(value || 0).toLocaleString()}
        </div>
        <div className="stat-lbl">{label}</div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────
function SevBadge({ severity }) {
  const c = SEV_COLOR[severity] || '#64748b'
  return (
    <span className="sev-badge"
      style={{ background: c + '22', color: c, border: `1px solid ${c}44` }}>
      {severity}
    </span>
  )
}

// ─────────────────────────────────────────
function GeoMap({ alerts }) {
  const threats = alerts
    .filter(a => a.lat && a.lon && a.lat !== 0 && a.lon !== 0)
    .slice(0, 50)

  if (threats.length === 0) {
    return (
      <div className="chart-card" style={{ marginBottom: 24 }}>
        <div className="chart-hdr">🌍 Live Attack Map</div>
        <div className="chart-empty" style={{ height: 200 }}>
          <span style={{ fontSize: 48 }}>🌍</span>
          <p>No geo-located threats yet — start capture and run attacks</p>
        </div>
      </div>
    )
  }

  return (
    <div className="chart-card" style={{ marginBottom: 24 }}>
      <div className="chart-hdr">
        🌍 Live Attack Map — {threats.length} threats plotted
      </div>

      <div style={{
        position: 'relative',
        background: '#0a0f1a',
        borderRadius: 4,
        overflow: 'hidden'
      }}>
        <svg viewBox="0 0 800 400" style={{ width: '100%', height: 'auto' }}>

          {/* Background */}
          <rect width="800" height="400" fill="#0a0f1a" />

          {/* Grid lines */}
          {[...Array(9)].map((_, i) => (
            <line key={`h${i}`}
              x1="0" y1={i * 50} x2="800" y2={i * 50}
              stroke="#1c2333" strokeWidth="0.5" />
          ))}
          {[...Array(17)].map((_, i) => (
            <line key={`v${i}`}
              x1={i * 50} y1="0" x2={i * 50} y2="400"
              stroke="#1c2333" strokeWidth="0.5" />
          ))}

          {/* Equator line */}
          <line x1="0" y1="200" x2="800" y2="200"
            stroke="#1c2333" strokeWidth="1"
            strokeDasharray="4,4" />

          {/* Prime meridian */}
          <line x1="400" y1="0" x2="400" y2="400"
            stroke="#1c2333" strokeWidth="1"
            strokeDasharray="4,4" />

          {/* Labels */}
          <text x="4" y="12" fill="#475569"
            fontSize="8" fontFamily="monospace">90°N</text>
          <text x="4" y="204" fill="#475569"
            fontSize="8" fontFamily="monospace">0°</text>
          <text x="4" y="396" fill="#475569"
            fontSize="8" fontFamily="monospace">90°S</text>

          {/* Attack dots */}
          {threats.map((threat, i) => {
            const x = ((threat.lon + 180) / 360) * 800
            const y = ((90 - threat.lat) / 180) * 400

            const color = threat.severity === 'CRITICAL' ? '#ff0044'
                        : threat.severity === 'HIGH'     ? '#ff3c6e'
                        : '#ffa500'

            return (
              <g key={i}>
                {/* Animated pulse ring */}
                <circle cx={x} cy={y} r="8"
                  fill="none"
                  stroke={color}
                  strokeWidth="1"
                  opacity="0.4">
                  <animate attributeName="r"
                    from="4" to="16"
                    dur="2s"
                    repeatCount="indefinite" />
                  <animate attributeName="opacity"
                    from="0.6" to="0"
                    dur="2s"
                    repeatCount="indefinite" />
                </circle>

                {/* Main dot */}
                <circle cx={x} cy={y} r="4"
                  fill={color}
                  opacity="0.9">
                  <title>
                    {threat.flag} {threat.country} — {threat.city}{'\n'}
                    Attack : {threat.attack_type}{'\n'}
                    IP     : {threat.src_ip}{'\n'}
                    ISP    : {threat.isp}
                  </title>
                </circle>
              </g>
            )
          })}
        </svg>

        {/* Legend */}
        <div style={{
          position: 'absolute', bottom: 8, right: 12,
          display: 'flex', gap: 16,
          fontSize: 11, fontFamily: 'monospace',
          color: '#64748b'
        }}>
          <span><span style={{ color: '#ff0044' }}>●</span> CRITICAL</span>
          <span><span style={{ color: '#ff3c6e' }}>●</span> HIGH</span>
          <span><span style={{ color: '#ffa500' }}>●</span> MEDIUM</span>
        </div>
      </div>

      {/* Country pills */}
      <div style={{
        display: 'flex', flexWrap: 'wrap',
        gap: 8, marginTop: 12
      }}>
        {[...new Map(
          threats.map(t => [t.country, t])
        ).values()].slice(0, 10).map((t, i) => (
          <div key={i} style={{
            background : 'rgba(255,60,110,0.08)',
            border     : '1px solid rgba(255,60,110,0.2)',
            padding    : '4px 10px',
            borderRadius: 2,
            fontSize   : 12,
            color      : '#94a3b8',
            fontFamily : 'monospace'
          }}>
            {t.flag} {t.country}
          </div>
        ))}
      </div>
    </div>
  )
}

// ─────────────────────────────────────────
export default function Dashboard() {
  const {
    stats, alerts, chartData,
    connected, capturing,
    startCapture, stopCapture, genReport
  } = useArgus()

  const [banner, setBanner] = useState('')

  const handleReport = async () => {
    setBanner('⏳ Generating report...')
    const r = await genReport()
    setBanner(
      r ? `✅ Saved → ${r.report_path}`
        : '❌ No alerts to report yet'
    )
    setTimeout(() => setBanner(''), 5000)
  }

  const atkData = [
    { name: 'DoS',         value: stats.dos_count     || 0 },
    { name: 'DDoS',        value: stats.dos_count     || 0 },
    { name: 'PortScan',    value: stats.probe_count   || 0 },
    { name: 'BruteForce',  value: stats.r2l_count     || 0 },
    { name: 'U2R',         value: stats.u2r_count     || 0 },
    { name: 'Unknown',     value: stats.unknown_count || 0 },
  ].filter(d => d.value > 0)

  return (
    <div className="dashboard">

      {/* ── NAVBAR ─────────────────────── */}
      <nav className="navbar">
        <div className="nav-brand">
          <Eye size={28} color="#00ff88" />
          <div>
            <div className="nav-logo">ARGUS</div>
            <div className="nav-sub">AI Network Intrusion Detection</div>
          </div>
        </div>
        <div className="nav-actions">
          <div className={`ws-badge ${connected ? 'online' : 'offline'}`}>
            {connected ? <Wifi size={13} /> : <WifiOff size={13} />}
            <span className="pulse" />
            {connected ? 'Live' : 'Offline'}
          </div>
          <button
            className={`btn ${capturing ? 'btn-red' : 'btn-green'}`}
            onClick={capturing ? stopCapture : startCapture}>
            {capturing
              ? <><Square size={13} /> Stop</>
              : <><Play  size={13} /> Start Capture</>}
          </button>
          <button className="btn btn-ghost" onClick={handleReport}>
            <FileText size={13} /> Report
          </button>
        </div>
      </nav>

      {banner && <div className="banner">{banner}</div>}

      <main className="main">

        {/* ── STAT CARDS ─────────────────── */}
        <div className="stats-grid">
          <StatCard icon={Activity}
            label="Total Flows"
            value={stats.total_flows}
            color="#4d9fff" />
          <StatCard icon={AlertTriangle}
            label="Threats"
            value={stats.total_threats}
            color="#ff3c6e" />
          <StatCard icon={Shield}
            label="Normal"
            value={stats.total_normal}
            color="#00ff88" />
          <StatCard icon={Zap}
            label="Anomalies"
            value={stats.unknown_count}
            color="#a855f7" />
        </div>

        {/* ── CHARTS ─────────────────────── */}
        <div className="charts-row">

          {/* Line Chart */}
          <div className="chart-card">
            <div className="chart-hdr">
              <Activity size={14} /> Live Traffic
            </div>
            {chartData.length === 0 ? (
              <div className="chart-empty">
                <Activity size={42} />
                <p>Start capture to see live data</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={chartData}>
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="#1c2333" />
                  <XAxis
                    dataKey="time"
                    stroke="#475569"
                    tick={{ fontSize: 10 }}
                    interval="preserveStartEnd" />
                  <YAxis
                    stroke="#475569"
                    tick={{ fontSize: 10 }}
                    allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      background  : '#0d1117',
                      border      : '1px solid #1c2333',
                      borderRadius: 3
                    }}
                    labelStyle={{ color: '#e2e8f0', fontSize: 11 }}
                  />
                  <Line type="monotone"
                    dataKey="flows"
                    stroke="#4d9fff"
                    strokeWidth={2}
                    dot={false}
                    name="Flows" />
                  <Line type="monotone"
                    dataKey="threats"
                    stroke="#ff3c6e"
                    strokeWidth={2}
                    dot={false}
                    name="Threats" />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Bar Chart */}
          <div className="chart-card">
            <div className="chart-hdr">
              <Shield size={14} /> Attack Types
            </div>
            {atkData.length === 0 ? (
              <div className="chart-empty">
                <Shield size={42} />
                <p>No attacks detected yet</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={atkData}>
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="#1c2333" />
                  <XAxis
                    dataKey="name"
                    stroke="#475569"
                    tick={{ fontSize: 11 }} />
                  <YAxis
                    stroke="#475569"
                    tick={{ fontSize: 11 }}
                    allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      background: '#0d1117',
                      border    : '1px solid #1c2333'
                    }}
                    labelStyle={{ color: '#e2e8f0' }}
                  />
                  <Bar dataKey="value" name="Count"
                    radius={[3, 3, 0, 0]}>
                    {atkData.map((d, i) => (
                      <Cell key={i}
                        fill={ATK_COLOR[d.name] || '#4d9fff'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* ── GEO MAP ──────────────────────── */}
        <GeoMap alerts={alerts} />

        {/* ── ALERT FEED ─────────────────── */}
        <div className="alerts-card">
          <div className="alerts-hdr">
            <div className="alerts-title">
              <AlertTriangle size={14} /> Live Alert Feed
            </div>
            <span className="alerts-count">{alerts.length} alerts</span>
          </div>

          {alerts.length === 0 ? (
            <div className="alerts-empty">
              <Shield size={48} />
              <p>No threats detected yet</p>
              <small>Start capture to begin monitoring your network</small>
            </div>
          ) : (
            <div>
              {alerts.map((a, i) => (
                <div key={i} className="alert-row">
                  <div className="alert-left">
                    <SevBadge severity={a.severity || 'HIGH'} />
                    <span className="attack-name"
                      style={{
                        color: ATK_COLOR[a.attack_type] || '#ff3c6e'
                      }}>
                      {a.attack_type}
                    </span>
                    {a.flag && (
                      <span style={{ fontSize: 16 }} title={a.country}>
                        {a.flag}
                      </span>
                    )}
                  </div>
                  <div className="alert-ips">
                    <code>{a.src_ip || '—'}</code>
                    <span className="arrow">→</span>
                    <code>{a.dst_ip || '—'}</code>
                    {a.city && a.city !== 'Unknown' && (
                      <span style={{
                        fontSize: 11,
                        color: '#475569',
                        fontFamily: 'monospace'
                      }}>
                        ({a.city})
                      </span>
                    )}
                  </div>
                  <div className="alert-right">
                    <span className="alert-proto">
                      {a.protocol || '—'}
                    </span>
                    <span className="alert-time">{a.timestamp}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

      </main>
    </div>
  )
}