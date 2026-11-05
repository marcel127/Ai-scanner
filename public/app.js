const STEPS = [
  ['QUEUED', 'Queued'],
  ['FETCHING_REPOSITORY', 'Fetching repository'],
  ['RUNNING_RULES', 'Running rules'],
  ['AI_ANALYSIS', 'AI analysis'],
  ['GENERATING_REVIEW', 'Generating review'],
  ['COMPLETED', 'Completed'],
];

const form = document.querySelector('#scan-form');
const input = document.querySelector('#github-url');
const start = document.querySelector('#start');
const formError = document.querySelector('#form-error');
const progress = document.querySelector('#progress');
const steps = document.querySelector('#steps');
const scanError = document.querySelector('#scan-error');
const result = document.querySelector('#result');

let timer = 0;

function showError(node, message) {
  node.hidden = !message;
  node.textContent = message || '';
}

function renderSteps(status) {
  const current = STEPS.findIndex(([value]) => value === status);
  steps.replaceChildren(
    ...STEPS.map(([value, label], index) => {
      const item = document.createElement('li');
      item.dataset.status = value;
      item.textContent = label;
      if (status === 'FAILED') {
        item.className = index === 0 ? 'current' : '';
      } else if (index < current || status === 'COMPLETED') {
        item.className = value === status ? 'current' : 'done';
      } else if (index === current) {
        item.className = 'current';
      }
      return item;
    }),
  );
}

function renderAiStatus(meta) {
  const notice = document.querySelector('#ai-status');
  const step = steps.querySelector('[data-status="AI_ANALYSIS"]');
  if (meta?.aiUsed === true) {
    notice.hidden = true;
    notice.textContent = '';
    return;
  }
  notice.hidden = false;
  notice.textContent = meta?.aiError
    ? 'AI analysis did not succeed. This review uses the deterministic rules only.'
    : 'AI analysis did not run. This review uses the deterministic rules only.';
  if (step) {
    step.className = 'skipped';
    step.textContent = 'AI analysis (not run)';
  }
}

function renderCoverage(meta) {
  const coverage = document.querySelector('#coverage');
  if (!meta?.truncated) {
    coverage.hidden = true;
    coverage.textContent = '';
    return;
  }
  coverage.hidden = false;
  coverage.textContent =
    meta.filesScanned === 0
      ? 'No eligible source files were scanned. This is not a complete security review.'
      : 'This scan is partial. Some files were skipped because of size limits, so this is not a complete security review.';
}

function renderReview(review) {
  renderAiStatus(review.meta);
  renderCoverage(review.meta);
  const risk = document.querySelector('#risk');
  risk.textContent = review.overallRisk;
  risk.className = `risk ${review.overallRisk}`;
  document.querySelector('#summary').textContent = review.summary;

  const counts = document.querySelector('#counts');
  counts.replaceChildren(
    ...Object.entries(review.severityCounts).map(([severity, count]) => {
      const item = document.createElement('li');
      item.textContent = `${severity}: ${count}`;
      return item;
    }),
  );

  const findings = document.querySelector('#findings');
  const groups = groupFindings(review.findings);
  findings.replaceChildren(
    ...(groups.length
      ? groups.map((group) => {
          const block = document.createElement('article');
          block.className = 'finding';
          const title = document.createElement('h4');
          title.textContent = `${group.severity} · ${group.title}`;
          const meta = document.createElement('p');
          meta.className = 'meta';
          meta.textContent = `${group.source} · ${group.category}`;
          const lines = document.createElement('ul');
          lines.className = 'occurrences';
          for (const finding of group.occurrences) {
            const item = document.createElement('li');
            const where = [finding.filePath, finding.lineStart ? `line ${finding.lineStart}` : '']
              .filter(Boolean)
              .join(', ');
            if (where) {
              const place = document.createElement('span');
              place.className = 'where';
              place.textContent = where;
              item.append(place);
            }
            const code = document.createElement('code');
            code.textContent = finding.evidence || where || finding.title;
            item.append(code);
            lines.append(item);
          }
          const fix = document.createElement('p');
          fix.className = 'fix';
          const fixLabel = document.createElement('span');
          fixLabel.textContent = 'How to fix';
          fix.append(fixLabel, document.createTextNode(group.remediation));
          const why = document.createElement('p');
          why.className = 'why';
          const whyLabel = document.createElement('span');
          whyLabel.textContent = 'Why it matters';
          why.append(whyLabel, document.createTextNode(group.whyItMatters));
          block.append(title, meta, lines, fix, why);
          return block;
        })
      : [emptyItem('No findings.')]),
  );
  result.hidden = false;
}

function groupFindings(findings) {
  const groups = [];
  const index = new Map();
  for (const finding of findings) {
    const key = `${finding.ruleId}|${finding.title}`;
    const existing = index.get(key);
    if (existing) {
      existing.occurrences.push(finding);
      continue;
    }
    const group = {
      severity: finding.severity,
      title: finding.title,
      source: finding.source,
      category: finding.category,
      remediation: finding.remediation,
      whyItMatters: finding.whyItMatters,
      occurrences: [finding],
    };
    index.set(key, group);
    groups.push(group);
  }
  return groups;
}

function emptyItem(text) {
  const item = document.createElement('li');
  item.textContent = text;
  return item;
}

async function readJson(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function stopPolling(message) {
  window.clearInterval(timer);
  showError(scanError, message);
  start.disabled = false;
}

async function poll(id) {
  try {
    const response = await fetch(`/api/scans/${id}`);
    if (!response.ok) {
      stopPolling('The scan could not be loaded.');
      return false;
    }
    const scan = await readJson(response);
    if (!scan || typeof scan.status !== 'string') {
      stopPolling('The scan could not be loaded.');
      return false;
    }
    renderSteps(scan.status);
    if (scan.status === 'FAILED') {
      stopPolling(scan.errorMessage || 'The scan failed.');
      return false;
    }
    if (scan.status !== 'COMPLETED') {
      return true;
    }
    start.disabled = false;
    const reviewResponse = await fetch(`/api/scans/${id}/result`);
    if (!reviewResponse.ok) {
      stopPolling('The review is not available yet.');
      return false;
    }
    const review = await readJson(reviewResponse);
    if (!review) {
      stopPolling('The review could not be loaded.');
      return false;
    }
    renderReview(review);
    return false;
  } catch {
    stopPolling('The scan could not be loaded. Check your connection and try again.');
    return false;
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  window.clearInterval(timer);
  showError(formError, '');
  showError(scanError, '');
  document.querySelector('#ai-status').hidden = true;
  document.querySelector('#coverage').hidden = true;
  result.hidden = true;
  start.disabled = true;

  try {
    const response = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ githubUrl: input.value }),
    });
    const body = await readJson(response);
    if (!response.ok || !body?.id) {
      showError(formError, body?.error || 'Could not start the scan.');
      start.disabled = false;
      return;
    }

    progress.hidden = false;
    renderSteps(body.status);
    const keepPolling = await poll(body.id);
    if (!keepPolling) {
      return;
    }
    timer = window.setInterval(() => {
      void poll(body.id)
        .then((keepGoing) => {
          if (!keepGoing) {
            window.clearInterval(timer);
          }
        })
        .catch(() => {
          stopPolling('The scan could not be loaded. Check your connection and try again.');
        });
    }, 1500);
  } catch {
    showError(formError, 'Could not start the scan. Check your connection and try again.');
    start.disabled = false;
  }
});
