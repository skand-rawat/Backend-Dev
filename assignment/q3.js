const fs = require("fs").promises;
const path = require("path");

async function syncDirectories(sourceDir, targetDir) {
  try {
    // Ensure target directory exists
    await fs.mkdir(targetDir, { recursive: true });

    // Read files in source and target
    const sourceFiles = await fs.readdir(sourceDir);
    const targetFiles = await fs.readdir(targetDir);

    for (const file of sourceFiles) {
      const sourcePath = path.join(sourceDir, file);
      const targetPath = path.join(targetDir, file);

      try {
        const sourceStat = await fs.stat(sourcePath);

        if (sourceStat.isFile()) {
          let shouldCopy = false;

          if (!targetFiles.includes(file)) {
            // File missing in target
            shouldCopy = true;
          } else {
            const targetStat = await fs.stat(targetPath);
            // Compare modification times
            if (sourceStat.mtimeMs > targetStat.mtimeMs) {
              shouldCopy = true;
            }
          }

          if (shouldCopy) {
            await fs.copyFile(sourcePath, targetPath);
            console.log(` Synced: ${file}`);
          }
        }
      } catch (err) {
        console.error(` Error processing file ${file}:`, err.message);
      }
    }

    console.log(" Synchronization complete!");
  } catch (err) {
    console.error("Error syncing directories:", err.message);
  }
}
syncDirectories("./source", "./target");
