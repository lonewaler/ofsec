import os

append_content = """

// ─── Initialize Event Listeners ─────────────
function initEventListeners() {
  const bind = (id, event, handler) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(event, handler);
  };

  bind('launch-scan-btn', 'click', launchScan);
  bind('btn-refresh-queue', 'click', loadQueueStatus);
  bind('btn-submit-queue', 'click', submitScanQueue);
  bind('btn-refresh-results', 'click', refreshResults);
  bind('btn-check-ip', 'click', checkIP);
  bind('btn-lookup-domain', 'click', lookupDomain);
  bind('btn-track-ioc', 'click', trackIOC);
  bind('btn-ask-ai', 'click', askAI);
  bind('btn-refresh-alerts', 'click', loadDefenseAlerts);
  bind('btn-export-json', 'click', exportReportJSON);
  bind('btn-export-html', 'click', exportReportHTML);
  bind('btn-retest-keys', 'click', loadAPIKeyStatus); 
  bind('btn-refresh-schedules', 'click', loadSchedules);
  bind('btn-create-schedule', 'click', createSchedule);
  bind('btn-change-password', 'click', changePassword);
  bind('btn-intel-sweep', 'click', runIntelSweep);
  bind('btn-refresh-notif', 'click', loadNotifConfig);
  bind('btn-test-alert', 'click', sendTestAlert);
  bind('btn-refresh-dlq', 'click', loadDLQ);
  bind('btn-retry-dlq', 'click', retryDLQ);

  const exportApiBtn = document.querySelector('[data-export-api="true"]');
  if (exportApiBtn) exportApiBtn.addEventListener('click', () => exportReportViaAPI('json'));
}

document.addEventListener('DOMContentLoaded', initEventListeners);
"""

file_path = r"c:\\Users\\DEL\\ofsec\\frontend\\js\\app.js"
with open(file_path, "a", encoding="utf-8") as f:
    f.write(append_content)

print("Successfully appended event listeners to app.js")
