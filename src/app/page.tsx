export default function Home() {
  return (
    <main style={{ maxWidth: 760, margin: "0 auto", padding: "64px 24px" }}>
      <h1 style={{ fontSize: 28, letterSpacing: 0.5 }}>
        KRYPTOS <span style={{ color: "#5b9dff" }}>Secret Broker</span>
      </h1>
      <p style={{ color: "#9aa4b2", lineHeight: 1.6 }}>
        Central broker for server-side secret usage. Authorized client applications request
        operations; the broker uses the secret internally, calls the provider and returns only
        the provider&apos;s response. Raw secrets are never retrievable through this service.
      </p>
      <ul style={{ color: "#9aa4b2", lineHeight: 1.9, paddingLeft: 20 }}>
        <li>
          <code style={code}>/api/health</code> — service &amp; provider availability
        </li>
        <li>
          <code style={code}>/api/v1/gemini</code>, <code style={code}>/api/v1/groq</code> — authenticated
          provider operations
        </li>
        <li>
          <a href="/admin" style={{ color: "#5b9dff" }}>
            /admin — operator dashboard
          </a>
        </li>
      </ul>
      <p style={{ color: "#5b6472", fontSize: 13, marginTop: 32 }}>
        There is no secret-retrieval API by design.
      </p>
    </main>
  );
}

const code: React.CSSProperties = {
  background: "#161b26",
  padding: "2px 6px",
  borderRadius: 4
};
