const fs = require("fs");
const readline = require("readline");

function analyzeLogFile(inputFile, outputFile = "summary_report.txt") {
  let totalLines = 0;
  let errorCount = 0;
  let warningCount = 0;
  let infoCount = 0;

  // Create a stream to read the file line by line
  const rl = readline.createInterface({
    input: fs.createReadStream(inputFile),
    crlfDelay: Infinity
  });

  rl.on("line", (line) => {
    totalLines++;
    if (line.includes("ERROR")) errorCount++;
    else if (line.includes("WARNING")) warningCount++;
    else if (line.includes("INFO")) infoCount++;
  });

  rl.on("close", () => {
    const summary = `
Log File Analysis Summary
=========================
Total lines: ${totalLines}
ERROR count: ${errorCount}
WARNING count: ${warningCount}
INFO count: ${infoCount}
`;

    // Write summary report using writeFile
    fs.writeFile(outputFile, summary, (err) => {
      if (err) {
        console.error(" Error writing summary:", err);
      } else {
        console.log(`Analysis complete. Summary written to ${outputFile}`);
      }
    });
  });
}

// Example usage:
analyzeLogFile("server.log");
