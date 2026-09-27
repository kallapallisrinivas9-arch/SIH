(() => {
  const root = document.documentElement;
  const saved = localStorage.getItem('sentinel-theme');
  if (saved) root.dataset.theme = saved;
  document.querySelector('#theme-toggle')?.addEventListener('click', () => { const next = root.dataset.theme === 'dark' ? 'light' : 'dark'; root.dataset.theme = next; localStorage.setItem('sentinel-theme', next); });
  const risk = window.SENTINEL_DATA?.risk || { critical: 0, review: 0, safe: 0 };
  const chart = document.querySelector('#risk-chart');
  if (chart && window.Chart) new Chart(chart, { type: 'doughnut', data: { labels: ['Critical', 'Review', 'Safe'], datasets: [{ data: [risk.critical, risk.review, risk.safe], backgroundColor: ['#e45d68', '#e9ad4d', '#48c39a'], borderWidth: 0, hoverOffset: 5 }] }, options: { cutout: '76%', plugins: { legend: { display: false }, tooltip: { callbacks: { label: item => ` ${item.label}: ${item.raw}` } } } } });
  const map = document.querySelector('#threat-map');
  const points = window.SENTINEL_DATA?.points || [];
  const escapeHtml = value => String(value ?? 'Unknown').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
  const showOfflineMap = () => {
    const offlineMap = document.querySelector('#offline-map');
    if (!offlineMap) return;
    offlineMap.classList.add('is-visible');
    offlineMap.innerHTML = `<div class="offline-map-title">OFFLINE ORIGIN VIEW · MAP TILES UNAVAILABLE</div><div class="offline-map-list">${points.length ? points.map(point => `<div class="offline-map-point"><i class="${escapeHtml(point.level)}"></i><span>${escapeHtml([point.city, point.country].filter(Boolean).join(', ') || 'Unknown location')}<small> · ${escapeHtml(point.ip)}</small></span><b>${escapeHtml(point.score)}/100</b></div>`).join('') : '<small>No source addresses available.</small>'}</div>`;
  };
  if (map && !window.L) showOfflineMap();
  if (map && window.L) {
    const view = L.map(map, { zoomControl: false, attributionControl: false }).setView([22.5, 78.9], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').on('tileerror', showOfflineMap).addTo(view);
    const knownLocations = {
      'frankfurt, germany': [50.1109, 8.6821],
      'mumbai, india': [19.076, 72.8777],
      'amsterdam, netherlands': [52.3676, 4.9041],
      'internal, private network': [20.5937, 78.9629]
    };
    const fallback = [22.5, 78.9];
    points.forEach((point, index) => {
      const location = [point.city, point.country].filter(Boolean).join(', ') || 'Unknown location';
      const knownCoords = knownLocations[location.toLowerCase()];
      const coords = Number.isFinite(point.latitude) && Number.isFinite(point.longitude)
        ? [point.latitude, point.longitude]
        : knownCoords || fallback;
      const levelColor = point.level === 'critical' ? '#e45d68' : '#e9ad4d';
      const precision = Number.isFinite(point.latitude) || knownCoords ? 'Location mapped' : 'Approximate demo position';
      const popup = `<div class="map-popup"><strong>${escapeHtml(location)}</strong><span class="map-popup-address">Source address: <b>${escapeHtml(point.ip)}</b></span><span>Risk ${escapeHtml(point.score)}/100 · ${escapeHtml(point.level)}</span><small>${precision}</small></div>`;
      L.circleMarker(coords, { radius: 7, color: levelColor, fillColor: levelColor, fillOpacity: .85, weight: 2 })
        .bindPopup(popup, { minWidth: 190 })
        .addTo(view);
    });
  }
  const filter = document.querySelector('#case-filter'); filter?.addEventListener('input', event => { const term = event.target.value.toLowerCase(); document.querySelectorAll('#case-rows tr').forEach(row => { row.hidden = term && !row.textContent.toLowerCase().includes(term); }); });
})();
