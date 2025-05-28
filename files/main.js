const BLOCKED_CATEGORIES = {
  13: 'games',
  144: 'domain sharing',
  134: 'security.malware',
  '-1': 'not reviewed',
  28: 'security.proxy',
  116: 'security.nettools',
  61: 'forums.im',
  94: 'porn.illicit',
  137: 'violence.extremism',
  113: 'parked'
}

async function checkDomains() {
  const input = document.getElementById('domainInput').value.trim();
  const domains = input.split('\n').map(d => d.trim()).filter(Boolean);
  const resultsDiv = document.getElementById('results');
  resultsDiv.innerHTML = '';

  const checks = domains.map(domain =>
    checkDomain(domain).then(result => renderResult(result, resultsDiv))
  );

  await Promise.allSettled(checks);
}

function renderResult(result, resultsDiv) {
  const entry = document.createElement('div');
  let className = 'entry ';
  let label = '';

  if (result.blocked) {
    className += 'blocked';
    label = BLOCKED_CATEGORIES[result.cat] || 'blocked';
  } else {
    className += 'unblocked';
    label = 'unblocked';
  }

  entry.className = className;
  entry.innerHTML = `<strong>${result.domain}</strong>: ${label}`;
  resultsDiv.appendChild(entry);
}

async function checkDomain(domain) {
  const payload = {
    query: `
      query getDeviceCategorization($itemA: CustomHostLookupInput!, $itemB: CustomHostLookupInput!) {
        a: custom_HostLookup(item: $itemA) {
          cat
          request { host }
        }
        b: custom_HostLookup(item: $itemB) {
          cat
          request { host }
        }
      }
    `,
    variables: {
      itemA: { hostname: domain, getArchive: true },
      itemB: { hostname: domain, getArchive: true }
    }
  }

  try {
    const res = await fetch('https://production-archive-proxy-api.lightspeedsystems.com/archiveproxy', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': 'onEkoztnFpTi3VG7XQEq6skQWN3aFm3h',
        'Accept': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    const cat = data?.data?.a?.cat ?? -1;
    const blocked = Object.keys(BLOCKED_CATEGORIES).includes(cat.toString());
    return { domain, cat, blocked };
  } catch (err) {
    return { domain, cat: -1, blocked: true };
  }
}
