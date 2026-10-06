// T35 — pruebas no funcionales del backend con k6.
// MODE=rendimiento|estres|ruptura|soak|escala  BASE=http://127.0.0.1:18200
// STUDENT/ADMIN/PASS: cuentas sintéticas del entorno de pruebas (nunca producción).
//
// Solo cuenta como éxito un 200/201: un 401 o 429 es una falla (corrección respecto
// del reporte inválido de 2026-10-08, que aceptaba 401).
import http from 'k6/http'
import { check, group } from 'k6'
import { Trend, Rate } from 'k6/metrics'

const BASE = __ENV.BASE || 'http://127.0.0.1:18200'
const MODE = __ENV.MODE || 'rendimiento'
const PASS = __ENV.PASS
const STUDENT = __ENV.STUDENT
const ADMIN = __ENV.ADMIN

const analyzeMs = new Trend('analyze_ms', true)
const listMs = new Trend('incidents_list_ms', true)
const detailMs = new Trend('incident_detail_ms', true)
const meMs = new Trend('auth_me_ms', true)
const ok = new Rate('ok_rate')

const SCENARIOS = {
  rendimiento: { executor: 'constant-vus', vus: Number(__ENV.VUS || 5), duration: __ENV.DUR || '2m' },
  estres: {
    executor: 'ramping-vus', startVUs: 1,
    stages: [
      { duration: '30s', target: 10 }, { duration: '30s', target: 25 },
      { duration: '30s', target: 50 }, { duration: '30s', target: 80 },
      { duration: '30s', target: 0 },
    ],
  },
  ruptura: {
    executor: 'ramping-vus', startVUs: 10,
    stages: [{ duration: '90s', target: 200 }, { duration: '30s', target: 200 }, { duration: '10s', target: 0 }],
  },
  soak: { executor: 'constant-vus', vus: Number(__ENV.VUS || 3), duration: __ENV.DUR || '10m' },
  escala: { executor: 'constant-vus', vus: Number(__ENV.VUS || 20), duration: __ENV.DUR || '90s' },
}

export const options = {
  scenarios: { [MODE]: SCENARIOS[MODE] },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  // La meta de la tesis (p95 de /analyze < 8 s) se mide; no se ajusta para pasar.
  thresholds: { analyze_ms: ['p(95)<8000'], ok_rate: ['rate>0.99'] },
}

// Solo dominios .test (RFC 2606): el probe no visita sitios reales durante la carga.
const URLS = [
  'https://login.paypal-verify.test/signin',
  'https://xn--pypal-4ve.test/account',
  'https://outlook-098.portal-login.test/login',
  'https://www.usbbog-campus.test/',
  'https://secure-update.example.test/confirm?id=42',
]

function login(user) {
  const r = http.post(`${BASE}/api/v1/auth/login`, JSON.stringify({ username: user, password: PASS }),
    { headers: { 'Content-Type': 'application/json', Origin: 'http://localhost:5173' } })
  return r.status === 200 ? r.json('access_token') : ''
}

export function setup() {
  const student = login(STUDENT)
  const admin = login(ADMIN)
  if (!student || !admin) throw new Error('login de setup falló: el entorno no está listo')
  return { student, admin }
}

export default function (data) {
  const s = { headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${data.student}`,
    Origin: 'http://localhost:5173' }, timeout: '60s' }
  const a = { headers: { Authorization: `Bearer ${data.admin}` }, timeout: '30s' }

  group('analyze', () => {
    const url = URLS[(__VU + __ITER) % URLS.length]
    const r = http.post(`${BASE}/api/v1/analyze`, JSON.stringify({ url }), s)
    analyzeMs.add(r.timings.duration)
    ok.add(check(r, { 'analyze 200': (x) => x.status === 200 }))
  })
  group('incidents', () => {
    const r = http.get(`${BASE}/api/v1/incidents?page_size=10`, a)
    listMs.add(r.timings.duration)
    ok.add(check(r, { 'incidents 200': (x) => x.status === 200 }))
    const items = r.status === 200 ? r.json('items') : []
    if (items && items.length) {
      const d = http.get(`${BASE}/api/v1/incidents/${items[0].id}`, a)
      detailMs.add(d.timings.duration)
      ok.add(check(d, { 'detail 200': (x) => x.status === 200 }))
    }
  })
  group('me', () => {
    const r = http.get(`${BASE}/api/v1/auth/me`, a)
    meMs.add(r.timings.duration)
    ok.add(check(r, { 'me 200': (x) => x.status === 200 }))
  })
}
