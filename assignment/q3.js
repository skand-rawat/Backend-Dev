const os = require('os');
const fs = require('fs');

function logSystemInfo() {
  const info = {
    timestamp: new Date().toISOString(),
    platform: os.platform(),
    cpu: os.cpus()[0].model,
    totalMemory: os.totalmem(),
    freeMemory: os.freemem()
  };

  const logEntry = `${info.timestamp} | Platform: ${info.platform} | CPU: ${info.cpu} | TotalMem: ${info.totalMemory} | FreeMem: ${info.freeMemory}\n`;

  fs.appendFile('systemInfo.log', logEntry, (err) => {
    if (err) console.error('Error writing log:', err);
  });
}
setInterval(logSystemInfo, 5000);

console.log('System logger started. Writing to systemInfo.log every 5 seconds...');
