const form = document.querySelector('#analysis-form');
if (form) {
  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = form.querySelector('button');
    const result = document.querySelector('#analysis-result');
    button.disabled = true;
    button.innerHTML = 'Analyzing signal <span>...</span>';
    try {
      const response = await fetch('/api/analyze', { method: 'POST', body: new FormData(form), headers: { 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content } });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Analysis failed');
      result.className = `${form.classList.contains('pro-form') ? 'pro-result' : 'result'} ${data.level}`;
      const location = data.location || {};
      const locationLabel = [location.city, location.country].filter(Boolean).join(', ') || 'Unknown';
      const radius = location.accuracy_radius_km ? `Approx. radius: ${location.accuracy_radius_km} km` : 'Exact radius unavailable';
      const coordinates = Number.isFinite(location.latitude) && Number.isFinite(location.longitude)
        ? `Coordinates: ${location.latitude.toFixed(5)}, ${location.longitude.toFixed(5)}`
        : 'Coordinates unavailable';
      result.innerHTML = `<div class="result-top"><span class="result-score">${escapeHtml(data.score)}<small>/100</small></span><div><b>${escapeHtml(data.verdict)}</b><p>Analysis complete. Evidence anchored.</p></div><a href="/cases/${escapeHtml(data.id)}">View case →</a></div><div class="result-location"><b>Location trace</b><span>${escapeHtml(locationLabel)}</span><span>Region: ${escapeHtml(location.region || 'Unknown')}</span><span>${escapeHtml(coordinates)}</span><span>Source address: ${escapeHtml(location.ip || 'Unknown')}</span><small>${escapeHtml(location.source || 'Unavailable')} · ${escapeHtml(radius)} · Confidence: ${escapeHtml(location.confidence || 'unknown')} · VPN: ${escapeHtml(location.vpn_status || 'not verified')}</small></div><div class="result-indicators">${data.indicators.map(item => `<span>+ ${escapeHtml(item)}</span>`).join('')}</div>`;
      form.reset();
    } catch (error) {
      result.className = `${form.classList.contains('pro-form') ? 'pro-result' : 'result'} critical`;
      result.innerHTML = `<b>Could not analyze</b><p>${error.message}</p>`;
    } finally {
      button.disabled = false;
      button.innerHTML = 'Run threat analysis <span>→</span>';
    }
  });
}
