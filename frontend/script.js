function fillExample(el) {
  document.getElementById("prompt").value = el.textContent;
}

async function checkPrompt() {
  const prompt = document.getElementById("prompt").value.trim();
  const box = document.getElementById("result");
  if (!prompt) { box.innerHTML = ""; return; }
  box.innerHTML = '<p style="text-align:center;color:#6b7280;margin-top:16px">Checking...</p>';

  try {
    const res = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt }),
    });
    const d = await res.json();
    const cls = d.malicious ? "blocked" : "allowed";
    box.innerHTML = `
      <div class="result ${cls}">
        <div class="verdict ${cls}">${d.verdict}</div>
        <div class="conf">Confidence: ${(d.confidence*100).toFixed(1)}%
          &nbsp;|&nbsp; Malicious probability: ${(d.malicious_probability*100).toFixed(1)}%</div>
      </div>`;
  } catch (e) {
    box.innerHTML = '<p style="text-align:center;color:#c0392b">Error reaching server.</p>';
  }
}
