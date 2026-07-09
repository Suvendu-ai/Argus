import { useState, useEffect, useRef } from 'react'
import axios from 'axios'

const API = 'http://localhost:8000'
const WS  = 'ws://localhost:8000/ws'

export function useArgus() {
  const [stats, setStats]         = useState({
    total_flows: 0, total_threats: 0, total_normal: 0,
    dos_count: 0, probe_count: 0, r2l_count: 0,
    u2r_count: 0, unknown_count: 0
  })
  const [alerts, setAlerts]       = useState([])
  const [chartData, setChartData] = useState([])
  const [connected, setConnected] = useState(false)
  const [capturing, setCapturing] = useState(false)

  const wsRef   = useRef(null)
  const prevRef = useRef({ total_flows: 0, total_threats: 0 })

  useEffect(() => {
    connect()
    return () => wsRef.current?.close()
  }, [])

  function connect() {
    try {
      const ws = new WebSocket(WS)
      wsRef.current = ws

      ws.onopen  = () => setConnected(true)
      ws.onclose = () => { setConnected(false); setTimeout(connect, 3000) }
      ws.onerror = () => setConnected(false)

      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data)

        // Update stats
        if (msg.stats) setStats(msg.stats)

        // Build chart data from heartbeat deltas
        if (msg.type === 'heartbeat' && msg.stats) {
          const t  = new Date().toLocaleTimeString('en', { hour12: false })
          const df = (msg.stats.total_flows   || 0) - prevRef.current.total_flows
          const dt = (msg.stats.total_threats || 0) - prevRef.current.total_threats
          prevRef.current = {
            total_flows   : msg.stats.total_flows   || 0,
            total_threats : msg.stats.total_threats || 0
          }
          setChartData(prev => [...prev.slice(-29), { time: t, flows: Math.max(0, df), threats: Math.max(0, dt) }])
        }

        // Initial state on connect
        if (msg.type === 'init') {
          setAlerts(msg.alerts || [])
        }

        // New alert
        if (msg.type === 'alert') {
          setAlerts(prev => [msg.data, ...prev].slice(0, 100))
        }
      }
    } catch (err) {
      setTimeout(connect, 3000)
    }
  }

  const startCapture = () =>
    axios.post(`${API}/capture/start`)
      .then(() => setCapturing(true))
      .catch(console.error)

  const stopCapture = () =>
    axios.post(`${API}/capture/stop`)
      .then(() => setCapturing(false))
      .catch(console.error)

  const genReport = () =>
    axios.post(`${API}/report/generate`)
      .then(r => r.data)
      .catch(() => null)

  return { stats, alerts, chartData, connected, capturing, startCapture, stopCapture, genReport }
}