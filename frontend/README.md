# ThreatLens Dashboard

Build a dark-themed SOC-style web app called "ThreatLens", an AI-Powered Cyber Threat Intelligence dashboard. Use React + Vite + TypeScript, Tailwind CSS, shadcn/ui, Recharts for charts, and React Flow for the attack graph. Use React Router for pages. No backend: put all data in a local mock data file (src/data/mock.ts) shaped like the REST API below, so it can be swapped for real API calls later.

DESIGN

- Dark SOC look: near-black background, slate cards, cyan accent, severity colours (Critical = red, High = orange, Medium = yellow, Low = green).

- Left sidebar navigation, top bar with a global search and a "Demo mode" toggle: "Attack data" / "Clean (benign) data".

- Dense, professional, readable. Fully responsive.

PAGES

1. Dashboard (/)

- KPI cards: total logs ingested, alerts raised, attacks detected, false-positive rate (show clearly).

- Risk score distribution donut/bar chart (Critical / High / Medium / Low).

- Alerts-over-time line chart.

- Incidents table sorted by risk score: ID, title, risk badge, confidence %, status, entities. Click a row to open it.

- When "Clean data" mode is on: show 0 alerts and a green banner "Clean logs → 0 alerts. No false alarms."

2. Incident Detail (/incidents/:id), the most important screen

- Header: incident title, risk gauge (0-100), confidence %, status, and action buttons: "Isolate host", "Block IP", "Disable account", "Export report" (mock toasts; Export downloads the incident JSON).

- Kill-chain stepper bar: Initial Access → Execution → Privilege Escalation → Lateral Movement → Collection → Exfiltration. Detected stages are highlighted, undetected ones greyed out. Map to MITRE ATT&CK IDs.

- Vertical attack timeline in chronological order. Every stage card MUST show timestamp, MITRE tactic, a "Reason" line, and an Evidence block with raw log lines (log ID, timestamp, source). Make it impossible to render a stage without evidence and reason: if either is missing, don't render the stage.

- Entities panel: users, hosts, IPs, apps as clickable chips linking to entity profiles.

- "Why flagged?" explanation panel: rule triggered, anomaly score, and feature-contribution horizontal bars (feature importance).

- Recommended actions list.

- "Replay attack" button that animates the timeline step by step, highlighting each stage in order.

3. Attack Graph (/graph/:incidentId)

- Interactive React Flow graph. Nodes = users, hosts, IPs, apps, files, with distinct icons. Edges = events (login, access, copy, connect) labelled with timestamps.

- Suspicious nodes and edges in red; the attack path highlighted and numbered in order.

- Click a node to open a side panel showing its related logs and incidents.

4. Log Explorer (/logs)

- Searchable, filterable table (time range, user, host, IP, event type, severity), sortable and paginated.

- Each row has a badge showing which incident/stage it belongs to (or "Benign"). Clicking opens a detail drawer with a link to that incident stage.

- Upload button (CSV/JSON drag-and-drop) that parses the file client-side and appends rows with a success toast.

5. Entity Profile (/entities/:type/:id)

- Baseline vs anomalous behaviour comparison (e.g., usual login hours/countries vs. observed).

- Anomaly score over time line chart for that entity.

- List of related incidents.

6. Metrics / Compare (/metrics)

- Precision, recall, F1, false-positive rate cards.

- "True labels vs detected" comparison table and confusion matrix.

7. Live feed (small widget on Dashboard)

- Simulated real-time alert stream that adds a new alert every few seconds, toggled on/off.

MOCK DATA (use this shape)

Incident INC-001 (alice, PC-12, IP 185.220.101.45), risk_score 92, confidence 0.94:

- Initial Access, 02:14, evidence log#1021, "Login from new country"

- Collection, 02:31, evidence log#1088, "Accessed 40 unseen files"

- Exfiltration, 02:40, evidence log#1102, "USB device copy"

- Recommendations: Disable alice, Isolate PC-12, Block IP

Add 2 more incidents (one slow and low-profile credential-abuse attack with Lateral Movement, one medium-risk) with full evidence logs, a graph (nodes and edges) for each, and about 300 mock log rows, mostly benign.

API SHAPE (mock these as functions in src/api.ts using React Query so real endpoints can replace them):

GET /incidents, GET /incidents/{id}, GET /graph/{incident_id}, GET /logs?user=&ip=&from=&to=, GET /entities/{type}/{id}, GET /metrics, POST /upload

Make every screen polished, with loading skeletons, empty states, and clear visual hierarchy.


## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
