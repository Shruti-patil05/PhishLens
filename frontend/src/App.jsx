
import React, { useState } from "react";

const API = "http://127.0.0.1:5000/api";

export default function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function analyzeUrl(event) {
    event.preventDefault();
    setError("");
    setResult(null);
    setLoading(true);

    try {
      const response = await fetch(`${API}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: url.trim(),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Analysis failed.");
      }

      setResult(data);
    } catch (err) {
      setError(
        err.message || "Could not connect to the backend."
      );
    } finally {
      setLoading(false);
    }
  }

  const riskLevel = result?.risk_level?.toLowerCase();

  const riskMessages = {
    low: {
      title: "SAFE URL",
      message:
        "No major suspicious patterns were detected. This URL appears safe based on the checks performed.",
    },
    medium: {
      title: "SUSPICIOUS URL",
      message:
        "Suspicious patterns were detected. This URL may be unsafe. Verify the website before proceeding or sharing personal information.",
    },
    high: {
      title: "UNSAFE URL",
      message:
        "Multiple suspicious patterns were detected. This URL may be dangerous. Avoid opening it or entering passwords, banking details, or other sensitive information.",
    },
  };

  return (
    <main className="app">
      <h1>PhishLens</h1>
      <h2>Explainable Phishing Detection</h2>

      <p>
        Enter a website URL to analyze its suspicious patterns.
      </p>

      <form onSubmit={analyzeUrl} className="url-form">
        <input
          type="text"
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          placeholder="https://example.com"
          aria-label="Website URL"
          required
        />

        <button type="submit" disabled={loading}>
          {loading ? "Analyzing..." : "Analyze URL"}
        </button>
      </form>

      {error && (
        <div className="error" role="alert">
          <strong>Error:</strong> {error}
        </div>
      )}

      {result && (
        <section className={`result ${riskLevel}`}>
          <h2>Analysis Result</h2>

          <p className="result-url">
            <strong>Website URL:</strong> {result.url}
          </p>

          <div className="score-container">
            <p>
              <strong>Risk Score</strong>
            </p>

            <p className="score">
              {result.risk_score}
              <span>/100</span>
            </p>
          </div>

          <p>
            <strong>Risk Level: </strong>
            <span className={`risk-badge ${riskLevel}`}>
              {result.risk_level}
            </span>
          </p>

          <h3>Why did PhishLens give this result?</h3>

          {Array.isArray(result.explanation) &&
          result.explanation.length > 0 ? (
            <ul className="explanation-list">
              {result.explanation.map((reason, index) => (
                <li key={index}>{reason}</li>
              ))}
            </ul>
          ) : (
            <p>
              No explanation was returned by the backend.
            </p>
          )}

          {riskMessages[riskLevel] && (
            <div className="result-message">
              <h3>{riskMessages[riskLevel].title}</h3>
              <p>{riskMessages[riskLevel].message}</p>
            </div>
          )}

          <p className="disclaimer">
            PhishLens uses rule-based checks. A low risk score
            does not guarantee that a website is safe, and a high
            risk score does not independently prove that it is
            malicious.
          </p>
        </section>
      )}
    </main>
  );
}
