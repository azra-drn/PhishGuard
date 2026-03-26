import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  Legend,
  ReferenceLine
} from "recharts";

const API = "http://127.0.0.1:8000";

const styles = {
  page: { minHeight: "100vh", background: "#f8fafc", padding: "24px" },
  container: { maxWidth: "1280px", margin: "0 auto" },
  title: { fontSize: "40px", fontWeight: "700", marginBottom: "6px", color: "#0f172a" },
  subtitle: { fontSize: "18px", color: "#475569", marginBottom: "24px" },
  tabs: { display: "flex", gap: "10px", marginBottom: "24px", flexWrap: "wrap" },
  tab: {
    border: "1px solid #cbd5e1",
    borderRadius: "12px",
    background: "#fff",
    padding: "10px 16px",
    cursor: "pointer",
    fontWeight: 600
  },
  activeTab: {
    background: "#0f172a",
    color: "#fff",
    border: "1px solid #0f172a"
  },
  grid2: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px" },
  grid4: { display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px" },
  card: {
    background: "#fff",
    borderRadius: "18px",
    padding: "22px",
    boxShadow: "0 8px 24px rgba(15,23,42,0.08)",
    marginBottom: "24px"
  },
  cardTitle: { fontSize: "26px", fontWeight: 600, marginBottom: "16px", color: "#0f172a" },
  input: {
    width: "100%",
    padding: "12px 14px",
    borderRadius: "12px",
    border: "1px solid #cbd5e1",
    marginBottom: "14px",
    fontSize: "15px"
  },
  textarea: {
    width: "100%",
    padding: "12px 14px",
    borderRadius: "12px",
    border: "1px solid #cbd5e1",
    marginBottom: "14px",
    fontSize: "15px",
    minHeight: "140px",
    resize: "vertical"
  },
  button: {
    background: "#0f172a",
    color: "#fff",
    border: "none",
    borderRadius: "12px",
    padding: "12px 18px",
    cursor: "pointer",
    fontWeight: 600
  },
  secondaryButton: {
    background: "#e2e8f0",
    color: "#0f172a",
    border: "none",
    borderRadius: "12px",
    padding: "12px 18px",
    cursor: "pointer",
    fontWeight: 600
  },
  table: { width: "100%", borderCollapse: "collapse" },
  th: { textAlign: "left", padding: "12px", borderBottom: "1px solid #e2e8f0" },
  td: { padding: "12px", borderBottom: "1px solid #e2e8f0", verticalAlign: "top" },
  badge: {
    display: "inline-block",
    padding: "8px 14px",
    borderRadius: "999px",
    fontWeight: 700,
    color: "#fff",
    marginBottom: "14px"
  },
  summaryNumber: { fontSize: "30px", fontWeight: 700, color: "#0f172a" },
  summaryLabel: { color: "#64748b", fontSize: "14px", marginTop: "8px" },
  infoBox: {
    background: "#f8fafc",
    border: "1px solid #e2e8f0",
    borderRadius: "12px",
    padding: "14px"
  }
};

const COLORS = ["#22c55e", "#f59e0b", "#ef4444"];

function riskBadgeColor(level) {
  if (level === "High") return "#ef4444";
  if (level === "Medium") return "#f59e0b";
  return "#22c55e";
}

export default function App() {
  const [tab, setTab] = useState("analyze");
  const [form, setForm] = useState({
    url: "",
    sender_email: "",
    subject: "",
    body: ""
  });
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [summary, setSummary] = useState(null);
  const [topRules, setTopRules] = useState([]);
  const [ruleLibrary, setRuleLibrary] = useState([]);
  const [riskFilter, setRiskFilter] = useState("All");
  const [searchTerm, setSearchTerm] = useState("");
  const [evaluation, setEvaluation] = useState(null);
  const [showAll, setShowAll] = useState(false);

  const fetchAll = async () => {
    try {
      const [historyRes, summaryRes, topRulesRes, rulesRes] = await Promise.all([
        axios.get(`${API}/history`),
        axios.get(`${API}/dashboard-summary`),
        axios.get(`${API}/top-rules`),
        axios.get(`${API}/rules`)
      ]);

      setHistory(historyRes.data || []);
      setSummary(summaryRes.data || null);
      setTopRules(topRulesRes.data || []);
      setRuleLibrary(rulesRes.data || []);
    } catch (err) {
      console.error("Dashboard fetch failed:", err);
    }
  };

  useEffect(() => {
    fetchAll();
  }, []);

  const handleAnalyze = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${API}/analyze`, form);
      setResult(res.data);
      await fetchAll();
      setTab("analyze");
    } catch (err) {
      console.error(err);
      alert("Analysis failed.");
    }
  };

  const handleDemoEvaluation = async () => {
    try {
      const res = await axios.get(`${API}/evaluate-demo`);
      setEvaluation(res.data);
      setShowAll(false);
    } catch (err) {
      console.error(err);
      alert("Demo evaluation failed.");
    }
  };

  const loadPhishingExample = () => {
    setForm({
      url: "http://192.168.1.1/login/verify/account/update",
      sender_email: "security@fake-bank.click",
      subject: "Urgent: Verify your password now",
      body: "Your account has been suspended. Click here to confirm your login immediately."
    });
  };

  const loadLegitimateExample = () => {
    setForm({
      url: "https://www.amazon.co.uk/orders/12345",
      sender_email: "orders@amazon.co.uk",
      subject: "Your Amazon order receipt",
      body: "Thank you for your order. You can view your receipt and order details in your Amazon account."
    });
  };

  const groupedRules = useMemo(() => {
    if (!result?.rule_details) return {};
    return result.rule_details.reduce((acc, rule) => {
      if (!acc[rule.category]) acc[rule.category] = [];
      acc[rule.category].push(rule);
      return acc;
    }, {});
  }, [result]);

  const filteredHistory = useMemo(() => {
    return history.filter((item) => {
      const matchesRisk = riskFilter === "All" || item.risk_level === riskFilter;
      const matchesSearch =
        (item.url || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
        (item.sender_email || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
        (item.subject || "").toLowerCase().includes(searchTerm.toLowerCase());
      return matchesRisk && matchesSearch;
    });
  }, [history, riskFilter, searchTerm]);

  const pieData = summary
    ? [
        { name: "Low", value: summary.low_risk },
        { name: "Medium", value: summary.medium_risk },
        { name: "High", value: summary.high_risk }
      ]
    : [];

  const trendData = history
    .slice()
    .reverse()
    .map((item, index) => ({
      scan: index + 1,
      score: item.score
    }));

  const confusionData = evaluation
    ? [
        { name: "TP", value: evaluation.metrics.true_positive },
        { name: "TN", value: evaluation.metrics.true_negative },
        { name: "FP", value: evaluation.metrics.false_positive },
        { name: "FN", value: evaluation.metrics.false_negative }
      ]
    : [];

  const actualVsPredictedData = evaluation
    ? [
        {
          name: "Phishing",
          actual: evaluation.actual_counts?.phishing || 0,
          predicted: evaluation.predicted_counts?.phishing || 0
        },
        {
          name: "Legitimate",
          actual: evaluation.actual_counts?.legitimate || 0,
          predicted: evaluation.predicted_counts?.legitimate || 0
        }
      ]
    : [];

  const demoRuleData = evaluation?.top_demo_rules || [];
  const displayedResults = showAll
    ? (evaluation?.full_results || evaluation?.preview_results || [])
    : (evaluation?.preview_results || []);

  const scoreThresholdData = result
    ? [
        { zone: "Current Score", score: result.score }
      ]
    : [];

  const topRiskFactors = result?.rule_details
    ? [...result.rule_details].sort((a, b) => b.points - a.points).slice(0, 5)
    : [];

  return (
    <div style={styles.page}>
      <div style={styles.container}>
        <h1 style={styles.title}>PhishGuard</h1>
        <p style={styles.subtitle}>
          Rule-Based Phishing Detection System with an Explainable Dashboard
        </p>

        <div style={styles.tabs}>
          {["analyze", "dashboard", "rules", "evaluation"].map((item) => (
            <button
              key={item}
              style={tab === item ? { ...styles.tab, ...styles.activeTab } : styles.tab}
              onClick={() => setTab(item)}
            >
              {item.charAt(0).toUpperCase() + item.slice(1)}
            </button>
          ))}
        </div>

        {tab === "analyze" && (
          <>
            <div style={styles.grid2}>
              <div style={styles.card}>
                <h2 style={styles.cardTitle}>Analyze Message</h2>

                <div style={{ display: "flex", gap: "12px", marginBottom: "16px", flexWrap: "wrap" }}>
                  <button style={styles.secondaryButton} type="button" onClick={loadPhishingExample}>
                    Load Phishing Example
                  </button>
                  <button style={styles.secondaryButton} type="button" onClick={loadLegitimateExample}>
                    Load Safe Example
                  </button>
                </div>

                <form onSubmit={handleAnalyze}>
                  <input
                    style={styles.input}
                    name="url"
                    placeholder="URL"
                    value={form.url}
                    onChange={(e) => setForm({ ...form, [e.target.name]: e.target.value })}
                  />
                  <input
                    style={styles.input}
                    name="sender_email"
                    placeholder="Sender Email"
                    value={form.sender_email}
                    onChange={(e) => setForm({ ...form, [e.target.name]: e.target.value })}
                  />
                  <input
                    style={styles.input}
                    name="subject"
                    placeholder="Email Subject"
                    value={form.subject}
                    onChange={(e) => setForm({ ...form, [e.target.name]: e.target.value })}
                  />
                  <textarea
                    style={styles.textarea}
                    name="body"
                    placeholder="Email Body"
                    value={form.body}
                    onChange={(e) => setForm({ ...form, [e.target.name]: e.target.value })}
                  />
                  <button style={styles.button} type="submit">
                    Analyze
                  </button>
                </form>
              </div>

              <div style={styles.card}>
                <h2 style={styles.cardTitle}>Latest Result</h2>

                {result ? (
                  <>
                    <div style={{ ...styles.badge, background: riskBadgeColor(result.risk_level) }}>
                      {result.risk_level} Risk
                    </div>

                    <p><strong>Score:</strong> {result.score}</p>
                    <p><strong>Explanation:</strong> {result.explanation}</p>

                    <div style={{ marginTop: "16px" }}>
                      <strong>Category Breakdown</strong>
                      <ul>
                        <li>URL-based: {result.category_scores["URL-based"]}</li>
                        <li>Sender-based: {result.category_scores["Sender-based"]}</li>
                        <li>Content-based: {result.category_scores["Content-based"]}</li>
                      </ul>
                    </div>

                    <div style={{ marginTop: "16px" }}>
                      <strong>Recommendations</strong>
                      <ul>
                        {result.recommendations.map((rec, i) => (
                          <li key={i}>{rec}</li>
                        ))}
                      </ul>
                    </div>
                  </>
                ) : (
                  <p>No analysis yet.</p>
                )}
              </div>
            </div>

            {result && (
              <>
                <div style={styles.grid2}>
                  <div style={styles.card}>
                    <h2 style={styles.cardTitle}>Decision Breakdown</h2>
                    <div style={styles.infoBox}>
                      <p><strong>Final score:</strong> {result.score}</p>
                      <p><strong>Decision:</strong> {result.risk_level} risk</p>
                      <p><strong>Classification rule:</strong> scores of 30 or above are treated as phishing-related.</p>
                    </div>

                    <div style={{ marginTop: "16px" }}>
                      <strong>Top contributing factors</strong>
                      <ul>
                        {topRiskFactors.map((rule, index) => (
                          <li key={index}>
                            <strong>{rule.name}</strong> — {rule.points} points
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  <div style={styles.card}>
                    <h2 style={styles.cardTitle}>Score Threshold Visualisation</h2>
                    <div style={{ width: "100%", height: 300 }}>
                      <ResponsiveContainer>
                        <BarChart data={scoreThresholdData}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="zone" />
                          <YAxis />
                          <Tooltip />
                          <ReferenceLine y={30} stroke="#ef4444" strokeDasharray="5 5" label="Threshold = 30" />
                          <Bar dataKey="score" fill="#2563eb" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                    <div style={styles.infoBox}>
                      <p><strong>0–29:</strong> legitimate / lower risk zone</p>
                      <p><strong>30+:</strong> phishing / elevated risk zone</p>
                    </div>
                  </div>
                </div>

                <div style={styles.card}>
                  <h2 style={styles.cardTitle}>Triggered Rules by Category</h2>
                  {Object.keys(groupedRules).map((category) => (
                    <div key={category} style={{ marginBottom: "18px" }}>
                      <h3>{category}</h3>
                      <ul>
                        {groupedRules[category].map((rule, index) => (
                          <li key={index}>
                            <strong>{rule.name}</strong> ({rule.points} points) — {rule.description}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              </>
            )}
          </>
        )}

        {tab === "dashboard" && (
          <>
            {!summary ? (
              <div style={styles.card}>
                <h2 style={styles.cardTitle}>Dashboard</h2>
                <p>Dashboard data could not be loaded yet.</p>
              </div>
            ) : (
              <>
                <div style={styles.grid4}>
                  <div style={styles.card}>
                    <div style={styles.summaryNumber}>{summary.total_scans}</div>
                    <div style={styles.summaryLabel}>Total Scans</div>
                  </div>
                  <div style={styles.card}>
                    <div style={styles.summaryNumber}>{summary.high_risk}</div>
                    <div style={styles.summaryLabel}>High Risk</div>
                  </div>
                  <div style={styles.card}>
                    <div style={styles.summaryNumber}>{summary.average_score}</div>
                    <div style={styles.summaryLabel}>Average Score</div>
                  </div>
                  <div style={styles.card}>
                    <div style={{ fontWeight: 700, fontSize: "18px" }}>
                      {summary.most_common_rule}
                    </div>
                    <div style={styles.summaryLabel}>Most Common Rule</div>
                  </div>
                </div>

                <div style={styles.grid2}>
                  <div style={styles.card}>
                    <h2 style={styles.cardTitle}>Risk Distribution</h2>
                    <div style={{ width: "100%", height: 320 }}>
                      <ResponsiveContainer>
                        <PieChart>
                          <Pie data={pieData} dataKey="value" nameKey="name" outerRadius={110} label>
                            {pieData.map((entry, index) => (
                              <Cell key={index} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  <div style={styles.card}>
                    <h2 style={styles.cardTitle}>Top Triggered Rules</h2>
                    <div style={{ width: "100%", height: 320 }}>
                      <ResponsiveContainer>
                        <BarChart data={topRules}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="rule" hide />
                          <YAxis allowDecimals={false} />
                          <Tooltip />
                          <Bar dataKey="count" fill="#ef4444" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                </div>

                <div style={styles.card}>
                  <h2 style={styles.cardTitle}>Score Trend</h2>
                  <div style={{ width: "100%", height: 300 }}>
                    <ResponsiveContainer>
                      <LineChart data={trendData}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="scan" />
                        <YAxis />
                        <Tooltip />
                        <Line type="monotone" dataKey="score" stroke="#2563eb" strokeWidth={2} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div style={styles.card}>
                  <h2 style={styles.cardTitle}>Scan History</h2>

                  <div style={{ display: "flex", gap: "12px", marginBottom: "16px", flexWrap: "wrap" }}>
                    <input
                      style={{ ...styles.input, marginBottom: 0, maxWidth: "320px" }}
                      placeholder="Search by URL, sender, or subject"
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                    />
                    <select
                      style={{ ...styles.input, marginBottom: 0, maxWidth: "180px" }}
                      value={riskFilter}
                      onChange={(e) => setRiskFilter(e.target.value)}
                    >
                      <option>All</option>
                      <option>Low</option>
                      <option>Medium</option>
                      <option>High</option>
                    </select>
                  </div>

                  <table style={styles.table}>
                    <thead>
                      <tr>
                        <th style={styles.th}>ID</th>
                        <th style={styles.th}>URL</th>
                        <th style={styles.th}>Sender</th>
                        <th style={styles.th}>Score</th>
                        <th style={styles.th}>Risk</th>
                        <th style={styles.th}>Rules</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredHistory.map((item) => (
                        <tr key={item.id}>
                          <td style={styles.td}>{item.id}</td>
                          <td style={styles.td}>{item.url || "-"}</td>
                          <td style={styles.td}>{item.sender_email || "-"}</td>
                          <td style={styles.td}>{item.score}</td>
                          <td style={styles.td}>
                            <span
                              style={{
                                ...styles.badge,
                                background: riskBadgeColor(item.risk_level),
                                padding: "6px 10px",
                                marginBottom: 0
                              }}
                            >
                              {item.risk_level}
                            </span>
                          </td>
                          <td style={styles.td}>{item.triggered_rules}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </>
        )}

        {tab === "rules" && (
          <div style={styles.card}>
            <h2 style={styles.cardTitle}>Rule Library</h2>
            <div style={styles.grid2}>
              {ruleLibrary.map((rule, index) => (
                <div
                  key={index}
                  style={{
                    border: "1px solid #e2e8f0",
                    borderRadius: "14px",
                    padding: "16px"
                  }}
                >
                  <h3 style={{ marginTop: 0 }}>{rule.name}</h3>
                  <p><strong>Category:</strong> {rule.category}</p>
                  <p><strong>Weight:</strong> {rule.points}</p>
                  <p>{rule.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === "evaluation" && (
          <>
            <div style={styles.card}>
              <h2 style={styles.cardTitle}>Evaluation</h2>
              <p>CSV upload is disabled for now. Use the built-in demo evaluation instead.</p>
              <button style={styles.button} onClick={handleDemoEvaluation}>
                Run Demo Evaluation
              </button>
            </div>

            {evaluation?.detected_mapping && (
              <div style={styles.card}>
                <h2 style={styles.cardTitle}>Evaluation Data Source</h2>
                <div style={styles.infoBox}>
                  <p><strong>Source:</strong> Built-in demo dataset</p>
                  <p><strong>Total samples:</strong> {evaluation.total_samples}</p>
                  <p><strong>Actual phishing samples:</strong> {evaluation.actual_counts?.phishing || 0}</p>
                  <p><strong>Actual legitimate samples:</strong> {evaluation.actual_counts?.legitimate || 0}</p>
                </div>
              </div>
            )}

            {evaluation && evaluation.metrics && (
              <>
                <div style={styles.card}>
                  <h2 style={styles.cardTitle}>How Demo Evaluation Works</h2>
                  <div style={styles.infoBox}>
                    <p><strong>Actual label:</strong> comes from the built-in demo dataset.</p>
                    <p><strong>Predicted label:</strong> is decided by the rule engine after scoring URL, sender, and content indicators.</p>
                    <p><strong>Decision threshold:</strong> if total score is 30 or above, the sample is classified as phishing; otherwise it is classified as legitimate.</p>
                  </div>
                </div>

                <div style={styles.card}>
                  <h2 style={styles.cardTitle}>Dataset Overview</h2>
                  <div style={styles.infoBox}>
                    <p><strong>Total URLs analyzed:</strong> {evaluation.total_samples}</p>
                    <p><strong>Currently shown:</strong> {displayedResults.length}</p>
                  </div>
                </div>

                <div style={styles.grid4}>
                  <div style={styles.card}>
                    <div style={styles.summaryNumber}>{evaluation.metrics.accuracy}</div>
                    <div style={styles.summaryLabel}>Accuracy</div>
                  </div>
                  <div style={styles.card}>
                    <div style={styles.summaryNumber}>{evaluation.metrics.precision}</div>
                    <div style={styles.summaryLabel}>Precision</div>
                  </div>
                  <div style={styles.card}>
                    <div style={styles.summaryNumber}>{evaluation.metrics.recall}</div>
                    <div style={styles.summaryLabel}>Recall</div>
                  </div>
                  <div style={styles.card}>
                    <div style={styles.summaryNumber}>{evaluation.metrics.f1_score}</div>
                    <div style={styles.summaryLabel}>F1 Score</div>
                  </div>
                </div>

                <div style={styles.grid2}>
                  <div style={styles.card}>
                    <h2 style={styles.cardTitle}>Actual vs Predicted</h2>
                    <div style={{ width: "100%", height: 300 }}>
                      <ResponsiveContainer>
                        <BarChart data={actualVsPredictedData}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="name" />
                          <YAxis allowDecimals={false} />
                          <Tooltip />
                          <Legend />
                          <Bar dataKey="actual" fill="#2563eb" />
                          <Bar dataKey="predicted" fill="#ef4444" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  <div style={styles.card}>
                    <h2 style={styles.cardTitle}>Confusion Matrix Overview</h2>
                    <div style={{ width: "100%", height: 300 }}>
                      <ResponsiveContainer>
                        <BarChart data={confusionData}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="name" />
                          <YAxis allowDecimals={false} />
                          <Tooltip />
                          <Bar dataKey="value" fill="#f59e0b" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                </div>

                <div style={styles.card}>
                  <h2 style={styles.cardTitle}>Confusion Summary</h2>
                  <p>True Positive: {evaluation.metrics.true_positive}</p>
                  <p>True Negative: {evaluation.metrics.true_negative}</p>
                  <p>False Positive: {evaluation.metrics.false_positive}</p>
                  <p>False Negative: {evaluation.metrics.false_negative}</p>
                </div>

                <div style={styles.card}>
                  <h2 style={styles.cardTitle}>Most Triggered Rules in Demo Evaluation</h2>
                  <div style={{ width: "100%", height: 320 }}>
                    <ResponsiveContainer>
                      <BarChart data={demoRuleData}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="rule" hide />
                        <YAxis allowDecimals={false} />
                        <Tooltip />
                        <Bar dataKey="count" fill="#dc2626" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div style={styles.card}>
                  <h2 style={styles.cardTitle}>Evaluation Interpretation</h2>
                  <div style={styles.infoBox}>
                    <p>
                      This evaluation shows how closely the rule-based predictions match the known labels
                      in the demo dataset. High true positives and true negatives indicate stronger
                      performance, while false positives and false negatives highlight areas where rule
                      weights or thresholds may need refinement.
                    </p>
                  </div>
                </div>

                <div style={styles.card}>
                  <h2 style={styles.cardTitle}>Preview Results</h2>

                  <div style={{ marginBottom: "16px" }}>
                    <button style={styles.button} onClick={() => setShowAll(!showAll)}>
                      {showAll ? "Show Preview Only" : "Show All Results"}
                    </button>
                  </div>

                  <table style={styles.table}>
                    <thead>
                      <tr>
                        <th style={styles.th}>Subject</th>
                        <th style={styles.th}>URL</th>
                        <th style={styles.th}>Actual</th>
                        <th style={styles.th}>Predicted</th>
                        <th style={styles.th}>Score</th>
                        <th style={styles.th}>Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {displayedResults.map((item, index) => (
                        <tr key={index}>
                          <td style={styles.td}>{item.subject || "-"}</td>
                          <td style={styles.td}>
                            <div style={{ maxWidth: "320px", wordBreak: "break-word" }}>
                              {item.url || "-"}
                            </div>
                          </td>
                          <td style={styles.td}>{item.actual_label}</td>
                          <td style={styles.td}>{item.predicted_label}</td>
                          <td style={styles.td}>{item.score}</td>
                          <td style={styles.td}>{item.risk_level}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}