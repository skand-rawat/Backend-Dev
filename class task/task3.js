const fs = require("fs");
const path = require("path");
const { promisify } = require("util");

const stat = promisify(fs.stat);
const mkdir = promisify(fs.mkdir);
const readdir = promisify(fs.readdir);
const copyFile = promisify(fs.copyFile);
const unlink = promisify(fs.unlink);
const appendFile = promisify(fs.appendFile);

async function backupAndCleanup(uploadDir, backupDir) {
  try {
    // Ensure upload directory exists
    if (!fs.existsSync(uploadDir)) {
      console.log("Upload directory does not exist.");
      return;
    }

    // Ensure backup directory exists
    if (!fs.existsSync(backupDir)) {
      await mkdir(backupDir, { recursive: true });
      console.log("Backup directory created.");
    }

    const files = await readdir(uploadDir);
    const now = Date.now();
    const sevenDays = 7 * 24 * 60 * 60 * 1000;

    for (const file of files) {
      const filePath = path.join(uploadDir, file);
      const stats = await stat(filePath);

      if (stats.isFile()) {
        // Backup file with timestamp
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
        const backupFileName = `${file}-${timestamp}`;
        const backupPath = path.join(backupDir, backupFileName);

        await copyFile(filePath, backupPath);
        await logOperation(`Backed up: ${file} -> ${backupFileName}`);

        // Delete if older than 7 days
        if (now - stats.mtimeMs > sevenDays) {
          await unlink(filePath);
          await logOperation(`Deleted old file: ${file}`);
        }
      }
    }

    console.log(" Backup and cleanup complete.");
  } catch (err) {
    console.error(" Error:", err);
  }
}

async function logOperation(message) {
  const logMessage = `[${new Date().toISOString()}] ${message}\n`;
  await appendFile("backup.log", logMessage);
}

// Example usage
backupAndCleanup("./uploads", "./backup");
