import express from "express";
import path from "path";
import fs from "fs";
import https from "https";
import os from "os";
import { createServer as createViteServer } from "vite";
import multer from "multer";
import { exec } from "child_process";
import AdmZip from "adm-zip";

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadsDir = path.join(process.cwd(), "uploads");
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const cleanName = path.basename(file.originalname);
    cb(null, cleanName);
  }
});
const upload = multer({ storage });

async function startServer() {
  const PORT = 3000;
  const app = express();

  // HTTPS SSL Configuration
  const keyPath = path.join(process.cwd(), "server.key");
  const certPath = path.join(process.cwd(), "server.cert");
  
  let useHttps = false;
  let httpsOptions: any = null;

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    try {
      httpsOptions = {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath)
      };
      useHttps = true;
      console.log("🔒 SSL Certificates found (server.key, server.cert). Preparing HTTPS configuration.");
    } catch (err: any) {
      console.error("❌ Failed to load SSL certificates. Falling back to standard HTTP:", err.message);
    }
  }

  // Enable proxy trust to support correct upstream client IP extraction (e.g. Cloud Run, nginx, GCP load balancers)
  app.set('trust proxy', true);

  // Set up high JSON body limits to support base64 document payloads
  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ limit: '50mb', extended: true }));

  // Core Directory Paths
  const DIR_DATA = path.join(process.cwd(), 'data');
  const DIR_UPLOADS = path.join(process.cwd(), 'uploads');
  const FILE_DB = path.join(DIR_DATA, 'db.json');

  // Try to repair db.json if it is corrupt/truncated
  if (fs.existsSync(FILE_DB)) {
    try {
      const content = fs.readFileSync(FILE_DB, 'utf-8');
      JSON.parse(content);
    } catch (err) {
      console.warn("⚠️ db.json is corrupt or truncated. Attempting automatic repair...");
      try {
        const content = fs.readFileSync(FILE_DB, 'utf-8');
        if (content.includes('"customLogo":')) {
          const partBeforeLogo = content.split('"customLogo":')[0];
          let cleaned = partBeforeLogo.trim();
          if (cleaned.endsWith(',')) {
            cleaned = cleaned.slice(0, -1);
          }
          cleaned += '\n  ,\n  "customLogo": null\n}';
          try {
            JSON.parse(cleaned);
            fs.writeFileSync(FILE_DB, cleaned, 'utf-8');
            console.log("✅ db.json repaired successfully!");
          } catch (innerErr) {
            console.error("❌ Failed to parse repaired JSON, resetting to safe shell:", innerErr);
            const emptyDb = { users: [], documents: [], auditLogs: [], dcrnRequests: [], loginSessions: [], customLogo: null };
            fs.writeFileSync(FILE_DB, JSON.stringify(emptyDb, null, 2), 'utf-8');
          }
        } else {
          console.error("❌ db.json is corrupted and could not be parsed. Resetting to empty database.");
          const emptyDb = { users: [], documents: [], auditLogs: [], dcrnRequests: [], loginSessions: [], customLogo: null };
          fs.writeFileSync(FILE_DB, JSON.stringify(emptyDb, null, 2), 'utf-8');
        }
      } catch (err2) {
        console.error("❌ Failed to repair db.json automatically:", err2);
      }
    }
  }

  // Ensure necessary directories exist
  if (!fs.existsSync(DIR_DATA)) {
    fs.mkdirSync(DIR_DATA, { recursive: true });
  }
  if (!fs.existsSync(DIR_UPLOADS)) {
    fs.mkdirSync(DIR_UPLOADS, { recursive: true });
  }

  const DIR_DCRNS = path.join(DIR_DATA, 'dcrns');
  if (!fs.existsSync(DIR_DCRNS)) {
    fs.mkdirSync(DIR_DCRNS, { recursive: true });
  }

  const DIR_CALIBRATIONS = path.join(DIR_DATA, 'calibrations');
  if (!fs.existsSync(DIR_CALIBRATIONS)) {
    fs.mkdirSync(DIR_CALIBRATIONS, { recursive: true });
  }

  // Calibration & Validation directories
  const DIR_CALVAL_BACKUPS = path.join(DIR_DATA, 'calval_backups');
  const DIR_CALVAL_UPLOADS = path.join(DIR_UPLOADS, 'calval');
  if (!fs.existsSync(DIR_CALVAL_BACKUPS)) {
    fs.mkdirSync(DIR_CALVAL_BACKUPS, { recursive: true });
  }
  if (!fs.existsSync(DIR_CALVAL_UPLOADS)) {
    fs.mkdirSync(DIR_CALVAL_UPLOADS, { recursive: true });
  }

  // Migrate any existing dcrnRequests in db.json to separate files
  if (fs.existsSync(FILE_DB)) {
    try {
      const content = fs.readFileSync(FILE_DB, 'utf-8');
      const parsed = JSON.parse(content);
      if (parsed.dcrnRequests && Array.isArray(parsed.dcrnRequests) && parsed.dcrnRequests.length > 0) {
        console.log(`[LAN-Server] Found ${parsed.dcrnRequests.length} DCRNs in db.json. Migrating to split storage...`);
        for (const req of parsed.dcrnRequests) {
          if (req && req.id) {
            const reqFile = path.join(DIR_DCRNS, `${req.id}.json`);
            if (!req.updatedAt) {
              req.updatedAt = req.createdAt || new Date().toISOString();
            }
            fs.writeFileSync(reqFile, JSON.stringify(req, null, 2), 'utf-8');
          }
        }
        parsed.dcrnRequests = [];
        fs.writeFileSync(FILE_DB, JSON.stringify(parsed, null, 2), 'utf-8');
        console.log("[LAN-Server] DCRN migration to split storage completed!");
      }
    } catch (err) {
      console.error("[LAN-Server] Failed to migrate existing DCRNs:", err);
    }
  }

  // Migrate any existing calibration records in calval_db.json to separate files
  const FILE_CALVAL_DB = path.join(DIR_DATA, 'calval_db.json');
  if (fs.existsSync(FILE_CALVAL_DB)) {
    try {
      const content = fs.readFileSync(FILE_CALVAL_DB, 'utf-8');
      const parsed = JSON.parse(content);
      if (parsed.records && Array.isArray(parsed.records) && parsed.records.length > 0) {
        console.log(`[LAN-Server] Found ${parsed.records.length} calibration records in calval_db.json. Migrating to split storage...`);
        for (const rec of parsed.records) {
          if (rec && rec.id) {
            const recFile = path.join(DIR_CALIBRATIONS, `${rec.id}.json`);
            fs.writeFileSync(recFile, JSON.stringify(rec, null, 2), 'utf-8');
          }
        }
        parsed.records = [];
        fs.writeFileSync(FILE_CALVAL_DB, JSON.stringify(parsed, null, 2), 'utf-8');
        console.log("[LAN-Server] Calibration records migration to split storage completed!");
      }
    } catch (err) {
      console.error("[LAN-Server] Failed to migrate existing calibration records:", err);
    }
  }

  // Intercept uploads and vault downloads with built-in Express native binary transfer handler
  app.get('/uploads/:filename', (req, res) => {
    try {
      const cleanFileName = path.basename(req.params.filename);
      const filePath = path.join(DIR_UPLOADS, cleanFileName);
      if (fs.existsSync(filePath)) {
        return res.download(filePath, cleanFileName, (err) => {
          if (err) {
            console.error("❌ Error during file transmission:", err);
          }
        });
      }
      return res.status(404).send('File not found');
    } catch (err: any) {
      return res.status(500).send(err.message);
    }
  });

  app.get('/vault/:folder/:filename', (req, res) => {
    try {
      const cleanFileName = path.basename(req.params.filename);
      const filePath = path.join(DIR_UPLOADS, cleanFileName);
      if (fs.existsSync(filePath)) {
        return res.download(filePath, cleanFileName, (err) => {
          if (err) {
            console.error("❌ Error during file transmission:", err);
          }
        });
      }
      return res.status(404).send('File not found');
    } catch (err: any) {
      return res.status(500).send(err.message);
    }
  });

  app.get('/api/download/:filename', (req, res) => {
    try {
      const fileName = req.params.filename;
      const filePath = path.join(DIR_UPLOADS, fileName);
      if (fs.existsSync(filePath)) {
        return res.download(filePath, fileName, (err) => {
          if (err) {
            console.error("❌ Error during file transmission:", err);
          }
        });
      } else {
        console.error(`❌ File not found on disk at: ${filePath}`);
        return res.status(404).send('File does not exist on the server storage.');
      }
    } catch (err: any) {
      return res.status(500).send(err.message);
    }
  });

  app.get('/api/download', (req, res) => {
    try {
      const { filename } = req.query;
      if (!filename) {
        return res.status(400).json({ error: 'Filename is required' });
      }
      const cleanFileName = path.basename(filename as string);
      const filePath = path.join(DIR_UPLOADS, cleanFileName);
      if (fs.existsSync(filePath)) {
        return res.download(filePath, cleanFileName, (err) => {
          if (err) {
            console.error("❌ Error during file transmission:", err);
          }
        });
      }
      return res.status(404).json({ error: 'File not found' });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // Serve uploaded files statically so they can be downloaded back as fallback
  app.use('/uploads', express.static(DIR_UPLOADS));

  // Fallback to alias /vault paths in case old records reference them
  app.use('/vault/mr-templates', express.static(DIR_UPLOADS));
  app.use('/vault/preparer-drafts', express.static(DIR_UPLOADS));
  app.use('/vault/reviewer-verified', express.static(DIR_UPLOADS));
  app.use('/vault/final-approved', express.static(DIR_UPLOADS));

  // ----------------------------------------------------
  // LOCAL PERSISTENT STORAGE CONTROLLER PATHS
  // ----------------------------------------------------

  // API to return client actual IP address
  app.get("/api/ip", (req, res) => {
    try {
      const forwarded = req.headers['x-forwarded-for'] || req.headers['x-real-ip'];
      const ip = forwarded || req.ip || req.socket.remoteAddress || '127.0.0.1';
      // If it has multiple IPs separated by comma (from proxies), grab the first client IP
      const cleanIp = typeof ip === 'string' ? ip.split(',')[0].trim() : ip;
      return res.json({ ip: cleanIp });
    } catch (err: any) {
      return res.json({ ip: '127.0.0.1' });
    }
  });

  // Safe DB reader helper to protect against JSON parsing and truncation errors
  const readDb = (): any => {
    if (!fs.existsSync(FILE_DB)) {
      return { users: [], documents: [], auditLogs: [], dcrnRequests: [], loginSessions: [], customLogo: null };
    }
    try {
      const content = fs.readFileSync(FILE_DB, 'utf-8');
      return JSON.parse(content);
    } catch (err) {
      console.warn("⚠️ db.json read parse failed. Running inline repair...");
      try {
        const content = fs.readFileSync(FILE_DB, 'utf-8');
        if (content.includes('"customLogo":')) {
          const partBeforeLogo = content.split('"customLogo":')[0];
          let cleaned = partBeforeLogo.trim();
          if (cleaned.endsWith(',')) {
            cleaned = cleaned.slice(0, -1);
          }
          cleaned += '\n  ,\n  "customLogo": null\n}';
          const parsed = JSON.parse(cleaned);
          fs.writeFileSync(FILE_DB, cleaned, 'utf-8');
          console.log("✅ db.json repaired inline successfully!");
          return parsed;
        }
      } catch (err2) {
        console.error("❌ Inline repair failed, returning fallback empty shell:", err2);
      }
      const emptyDb = { users: [], documents: [], auditLogs: [], dcrnRequests: [], loginSessions: [], customLogo: null };
      try {
        fs.writeFileSync(FILE_DB, JSON.stringify(emptyDb, null, 2), 'utf-8');
      } catch (e) {}
      return emptyDb;
    }
  };

  // Helper to load all DCRNs from split storage
  const loadDcrnRequests = (): any[] => {
    try {
      if (!fs.existsSync(DIR_DCRNS)) {
        return [];
      }
      const files = fs.readdirSync(DIR_DCRNS);
      const requests: any[] = [];
      for (const file of files) {
        if (file.endsWith('.json')) {
          try {
            const filePath = path.join(DIR_DCRNS, file);
            const content = fs.readFileSync(filePath, 'utf-8');
            const parsed = JSON.parse(content);
            requests.push(parsed);
          } catch (e) {
            console.error(`Error parsing DCRN file ${file}`, e);
          }
        }
      }
      return requests;
    } catch (err) {
      console.error("Failed to read DCRN files", err);
      return [];
    }
  };

  // Helper to load all Calibration/Validation records from split storage
  const loadCalibrationRecords = (): any[] => {
    try {
      if (!fs.existsSync(DIR_CALIBRATIONS)) {
        return [];
      }
      const files = fs.readdirSync(DIR_CALIBRATIONS);
      const records: any[] = [];
      for (const file of files) {
        if (file.endsWith('.json')) {
          try {
            const filePath = path.join(DIR_CALIBRATIONS, file);
            const content = fs.readFileSync(filePath, 'utf-8');
            const parsed = JSON.parse(content);
            records.push(parsed);
          } catch (e) {
            console.error(`Error parsing Calibration file ${file}`, e);
          }
        }
      }
      return records;
    } catch (err) {
      console.error("Failed to read Calibration files", err);
      return [];
    }
  };

  // API to load database state
  app.get("/api/data", (req, res) => {
    try {
      const dcrns = loadDcrnRequests();
      const parsed = readDb();
      return res.json({
        users: parsed.users || [],
        documents: parsed.documents || [],
        auditLogs: parsed.auditLogs || [],
        dcrnRequests: dcrns,
        loginSessions: parsed.loginSessions || [],
        customLogo: parsed.customLogo || null
      });
    } catch (err: any) {
      console.error("Error reading db.json", err);
      res.status(500).json({ error: "Failed to read database state" });
    }
  });

  // API to save/sync database state
  app.post("/api/sync", (req, res) => {
    try {
      const { users, documents, auditLogs, dcrnRequests, loginSessions, customLogo } = req.body;
      
      // Save main db fields to db.json (leaving dcrnRequests empty in main file to save space)
      const model = {
        users: users || [],
        documents: documents || [],
        auditLogs: auditLogs || [],
        dcrnRequests: [],
        loginSessions: loginSessions || [],
        customLogo: customLogo || null
      };
      fs.writeFileSync(FILE_DB, JSON.stringify(model, null, 2), 'utf-8');

      // Process and merge incoming DCRN requests individually
      if (dcrnRequests && Array.isArray(dcrnRequests)) {
        for (const incoming of dcrnRequests) {
          if (!incoming || !incoming.id) continue;
          
          const filePath = path.join(DIR_DCRNS, `${incoming.id}.json`);
          let shouldOverwrite = false;

          if (!fs.existsSync(filePath)) {
            shouldOverwrite = true;
          } else {
            try {
              const existingContent = fs.readFileSync(filePath, 'utf-8');
              const existing = JSON.parse(existingContent);
              
              const incomingTime = incoming.updatedAt ? new Date(incoming.updatedAt).getTime() : 0;
              const existingTime = existing.updatedAt ? new Date(existing.updatedAt).getTime() : 0;
              
              if (incomingTime > existingTime) {
                shouldOverwrite = true;
              } else if (incomingTime === existingTime) {
                if (JSON.stringify(incoming) !== JSON.stringify(existing)) {
                  shouldOverwrite = true;
                }
              }
            } catch (e) {
              shouldOverwrite = true; // if existing file is corrupted, overwrite it
            }
          }

          if (shouldOverwrite) {
            if (!incoming.updatedAt) {
              incoming.updatedAt = new Date().toISOString();
            }
            fs.writeFileSync(filePath, JSON.stringify(incoming, null, 2), 'utf-8');
          }
        }
      }

      res.json({ success: true });
    } catch (err: any) {
      console.error("Error writing db.json or dcrns", err);
      res.status(500).json({ error: "Failed to sync database state" });
    }
  });

  // API to upload binary files (supports both base64 transport and standard FormData/multipart)
  app.post(['/uploads', '/api/upload'], upload.any(), (req, res) => {
    try {
      if (req.files && Array.isArray(req.files) && req.files.length > 0) {
        const file = req.files[0];
        const cleanFileName = path.basename(file.originalname);
        const destinationPath = path.join(DIR_UPLOADS, cleanFileName);
        const fileSizeInKb = (file.size / 1024).toFixed(0);
        const fileSizeFormatted = `${fileSizeInKb} KB`;

        // Ensure directory exists synchronously before moving
        if (!fs.existsSync(DIR_UPLOADS)) {
          fs.mkdirSync(DIR_UPLOADS, { recursive: true });
        }

        const sourcePath = path.resolve(file.path);
        const destPath = path.resolve(destinationPath);
        if (sourcePath !== destPath) {
          fs.copyFileSync(file.path, destinationPath);
          fs.unlinkSync(file.path);
        }
        console.log(`[LAN-Server] Saved file from multipart upload: ${destinationPath} (${fileSizeFormatted})`);

        return res.json({
          success: true,
          filename: cleanFileName,
          fileName: cleanFileName,
          url: `/uploads/${cleanFileName}`,
          fileSize: fileSizeFormatted
        });
      }

      // If no multipart files, check if it's base64 in body
      const { fileName, base64Data } = req.body || {};
      if (fileName && base64Data) {
        // Sanitize file name to prevent directory traversal
        const cleanFileName = path.basename(fileName);
        const destinationPath = path.join(DIR_UPLOADS, cleanFileName);

        // Convert base64 data back to physical file buffer
        const fileBuffer = Buffer.from(base64Data, 'base64');
        fs.writeFileSync(destinationPath, fileBuffer);

        // Calculate simulated filesize representation
        const fileSizeInKb = (fileBuffer.length / 1024).toFixed(0);
        const fileSizeFormatted = `${fileSizeInKb} KB`;

        console.log(`[LAN-Server] Saved file locally from base64: ${destinationPath} (${fileSizeFormatted})`);

        return res.json({
          success: true,
          filename: cleanFileName,
          fileName: cleanFileName,
          url: `/uploads/${cleanFileName}`,
          fileSize: fileSizeFormatted
        });
      }

      return res.status(400).json({ error: 'No file received by backend.' });
    } catch (err: any) {
      console.error(err);
      return res.status(500).json({ error: err.message || "Failed to save file on LAN host server disk" });
    }
  });

  // ----------------------------------------------------
  // OVER-THE-AIR (OTA) HOT-PATCH & APP UPDATES ROUTER
  // ----------------------------------------------------
  const DIR_UPDATES = path.join(process.cwd(), 'updates');
  if (!fs.existsSync(DIR_UPDATES)) {
    fs.mkdirSync(DIR_UPDATES, { recursive: true });
  }

  interface UpdateStatus {
    stage: string;
    progress: number;
    log: string[];
    error: string | null;
  }

  const updateStatus: UpdateStatus = {
    stage: "idle",
    progress: 0,
    log: [],
    error: null
  };

  function getFilesRecursively(dir: string, baseDir: string = dir): string[] {
    let results: string[] = [];
    if (!fs.existsSync(dir)) return results;
    try {
      const list = fs.readdirSync(dir);
      for (const file of list) {
        const fullPath = path.join(dir, file);
        const stat = fs.statSync(fullPath);
        if (stat && stat.isDirectory()) {
          results = results.concat(getFilesRecursively(fullPath, baseDir));
        } else {
          const relPath = path.relative(baseDir, fullPath).replace(/\\/g, '/');
          results.push(relPath);
        }
      }
    } catch (e: any) {
      console.error("Error listing update files recursively:", e);
    }
    return results;
  }

  // Get current update status and list of pending files in /updates/
  app.get("/api/admin/updates/status", (req, res) => {
    try {
      // Check if there is a .zip file placed directly inside DIR_UPDATES
      let localZipFile: string | null = null;
      if (fs.existsSync(DIR_UPDATES)) {
        const files = fs.readdirSync(DIR_UPDATES);
        const zip = files.find(f => f.toLowerCase().endsWith('.zip'));
        if (zip) {
          localZipFile = zip;
        }
      }

      const pendingFiles = getFilesRecursively(DIR_UPDATES);
      return res.json({
        stage: updateStatus.stage,
        progress: updateStatus.progress,
        log: updateStatus.log,
        error: updateStatus.error,
        pendingFiles,
        localZipFile,
        hasRollback: fs.existsSync(path.join(process.cwd(), 'backups', 'rollback_manifest.json'))
      });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // Extract a locally placed ZIP file inside the /updates folder
  app.post("/api/admin/updates/extract-local", (req, res) => {
    try {
      if (!fs.existsSync(DIR_UPDATES)) {
        return res.status(400).json({ error: "Updates directory does not exist." });
      }
      const files = fs.readdirSync(DIR_UPDATES);
      const zipName = files.find(f => f.toLowerCase().endsWith('.zip'));
      if (!zipName) {
        return res.status(400).json({ error: "No ZIP file found inside the updates/ folder." });
      }

      const zipPath = path.join(DIR_UPDATES, zipName);
      updateStatus.stage = "extracting";
      updateStatus.progress = 30;
      updateStatus.log = [`Found local ZIP archive: ${zipName}`, "Extracting updates locally..."];
      updateStatus.error = null;

      try {
        // Copy ZIP to temporary location in uploads folder first so we can safely clean DIR_UPDATES
        const tempDir = path.join(process.cwd(), 'uploads');
        if (!fs.existsSync(tempDir)) {
          fs.mkdirSync(tempDir, { recursive: true });
        }
        const tempZipCopy = path.join(tempDir, `temp_${Date.now()}_${zipName}`);
        fs.copyFileSync(zipPath, tempZipCopy);

        // Clean updates directory to prepare for clean extraction
        fs.rmSync(DIR_UPDATES, { recursive: true, force: true });
        fs.mkdirSync(DIR_UPDATES, { recursive: true });

        // Extract from temp copy to updates directory
        const tempZip = new AdmZip(tempZipCopy);
        tempZip.extractAllTo(DIR_UPDATES, true);

        // Remove temp copy
        try {
          fs.unlinkSync(tempZipCopy);
        } catch (e) {}

        updateStatus.stage = "idle";
        updateStatus.progress = 0;
        updateStatus.log.push(`✅ ZIP package "${zipName}" extracted successfully!`);
        updateStatus.log.push(`Pending files listed below. Ready to apply.`);

        return res.json({ 
          success: true, 
          message: `Local archive "${zipName}" detected and extracted successfully. Ready to apply.` 
        });
      } catch (zipErr: any) {
        updateStatus.stage = "failed";
        updateStatus.error = zipErr.message;
        updateStatus.log.push(`❌ Local ZIP extraction failed: ${zipErr.message}`);
        return res.status(500).json({ error: "Failed to parse local ZIP file: " + zipErr.message });
      }
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // Clear/Reset pending updates folder
  app.post("/api/admin/updates/clear", (req, res) => {
    try {
      if (fs.existsSync(DIR_UPDATES)) {
        fs.rmSync(DIR_UPDATES, { recursive: true, force: true });
      }
      fs.mkdirSync(DIR_UPDATES, { recursive: true });
      
      updateStatus.stage = "idle";
      updateStatus.progress = 0;
      updateStatus.log = ["Pending updates cleared."];
      updateStatus.error = null;

      return res.json({ success: true, message: "Pending updates cleared successfully." });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // Upload an update ZIP archive or single update file
  app.post("/api/admin/updates/upload", upload.any(), (req, res) => {
    try {
      if (req.files && Array.isArray(req.files) && req.files.length > 0) {
        const file = req.files[0];
        const fileExtension = path.extname(file.originalname).toLowerCase();
        
        // Ensure updates directory exists
        if (!fs.existsSync(DIR_UPDATES)) {
          fs.mkdirSync(DIR_UPDATES, { recursive: true });
        }

        if (fileExtension === '.zip') {
          updateStatus.stage = "extracting";
          updateStatus.progress = 20;
          updateStatus.log = [`Found ZIP archive: ${file.originalname}`, "Extracting updates..."];
          updateStatus.error = null;

          try {
            const zip = new AdmZip(file.path);
            
            // Clean up old update files first
            fs.rmSync(DIR_UPDATES, { recursive: true, force: true });
            fs.mkdirSync(DIR_UPDATES, { recursive: true });
            
            zip.extractAllTo(DIR_UPDATES, true);
            
            // Clean up temporary uploaded file from /uploads so it doesn't clutter
            try {
              fs.unlinkSync(file.path);
            } catch (e) {}

            updateStatus.stage = "idle";
            updateStatus.progress = 0;
            updateStatus.log.push("ZIP package extracted successfully! Ready to apply.");
            
            return res.json({ 
              success: true, 
              message: "ZIP archive extracted successfully. View files in list below." 
            });
          } catch (zipErr: any) {
            updateStatus.stage = "failed";
            updateStatus.error = zipErr.message;
            updateStatus.log.push(`ZIP extraction failed: ${zipErr.message}`);
            return res.status(500).json({ error: "Failed to parse ZIP file: " + zipErr.message });
          }
        } else {
          // Standard single file update
          const cleanFileName = file.originalname;
          const targetPath = path.join(DIR_UPDATES, cleanFileName);
          
          // Make sure parent dirs inside updates exist if there's nested folders
          const parentDir = path.dirname(targetPath);
          if (!fs.existsSync(parentDir)) {
            fs.mkdirSync(parentDir, { recursive: true });
          }

          fs.copyFileSync(file.path, targetPath);
          try {
            fs.unlinkSync(file.path);
          } catch (e) {}

          updateStatus.log.push(`Received file: ${cleanFileName}`);
          return res.json({ success: true, message: `Saved file ${cleanFileName} successfully.` });
        }
      }
      return res.status(400).json({ error: "No file received for updates." });
    } catch (err: any) {
      console.error("Error in updates upload:", err);
      return res.status(500).json({ error: err.message });
    }
  });

  // Apply pending updates and compile build
  app.post("/api/admin/updates/apply", (req, res) => {
    try {
      if (updateStatus.stage === "applying" || updateStatus.stage === "building") {
        return res.status(400).json({ error: "An update or compilation process is already running." });
      }

      const pendingFiles = getFilesRecursively(DIR_UPDATES);
      if (pendingFiles.length === 0) {
        return res.status(400).json({ error: "No pending update files found to apply." });
      }

      updateStatus.stage = "applying";
      updateStatus.progress = 30;
      updateStatus.log = ["Starting application of files..."];
      updateStatus.error = null;

      // Create a rollback backup point before applying updates
      try {
        const rollbackZip = new AdmZip();
        const rollbackManifest = {
          timestamp: new Date().toISOString(),
          originalFiles: [] as string[],
          newFiles: [] as string[]
        };

        for (const relPath of pendingFiles) {
          // Security checks aligned with below
          if (
            relPath.startsWith('data/') || 
            relPath.startsWith('uploads/') || 
            relPath === '.env' ||
            relPath === 'package-lock.json' ||
            relPath.startsWith('.git/')
          ) {
            continue;
          }

          const targetPath = path.join(process.cwd(), relPath);
          if (fs.existsSync(targetPath)) {
            const zipDir = path.dirname(relPath);
            const zipFolder = zipDir === '.' ? '' : zipDir;
            rollbackZip.addLocalFile(targetPath, zipFolder);
            rollbackManifest.originalFiles.push(relPath);
          } else {
            rollbackManifest.newFiles.push(relPath);
          }
        }

        const DIR_BACKUPS = path.join(process.cwd(), 'backups');
        if (!fs.existsSync(DIR_BACKUPS)) {
          fs.mkdirSync(DIR_BACKUPS, { recursive: true });
        }

        if (rollbackManifest.originalFiles.length > 0 || rollbackManifest.newFiles.length > 0) {
          rollbackZip.writeZip(path.join(DIR_BACKUPS, 'rollback_latest.zip'));
          fs.writeFileSync(
            path.join(DIR_BACKUPS, 'rollback_manifest.json'),
            JSON.stringify(rollbackManifest, null, 2)
          );
          updateStatus.log.push("💾 Rollback snapshot created successfully.");
        }
      } catch (rollbackErr: any) {
        updateStatus.log.push(`⚠️ Failed to create rollback snapshot: ${rollbackErr.message}`);
      }

      // Copy files to main working directory
      let appliedCount = 0;
      let skippedCount = 0;

      for (const relPath of pendingFiles) {
        const sourcePath = path.join(DIR_UPDATES, relPath);
        const targetPath = path.join(process.cwd(), relPath);

        // Security check: Never overwrite database, custom logs, or environment files
        if (
          relPath.startsWith('data/') || 
          relPath.startsWith('uploads/') || 
          relPath === '.env' ||
          relPath === 'package-lock.json' ||
          relPath.startsWith('.git/')
        ) {
          updateStatus.log.push(`⚠️ Skipped secure/system file: ${relPath}`);
          skippedCount++;
          continue;
        }

        // Ensure target parent directory exists
        const targetParentDir = path.dirname(targetPath);
        if (!fs.existsSync(targetParentDir)) {
          fs.mkdirSync(targetParentDir, { recursive: true });
        }

        fs.copyFileSync(sourcePath, targetPath);
        updateStatus.log.push(`✅ Applied: ${relPath}`);
        appliedCount++;
      }

      updateStatus.log.push(`File application complete. Applied: ${appliedCount}, Skipped: ${skippedCount}.`);
      updateStatus.stage = "building";
      updateStatus.progress = 60;
      updateStatus.log.push("Compiling application assets (npm run build)...");

      // Spawn build execution
      exec("npm run build", { cwd: process.cwd() }, (err, stdout, stderr) => {
        if (err) {
          console.error("Compilation failed during update build:", err);
          updateStatus.stage = "failed";
          updateStatus.error = err.message || "Compilation failed";
          updateStatus.log.push(`❌ Compilation Failed: ${err.message}`);
          if (stderr) updateStatus.log.push(stderr);
        } else {
          console.log("Compilation succeeded!");
          updateStatus.stage = "completed";
          updateStatus.progress = 100;
          updateStatus.log.push("=================================================");
          updateStatus.log.push("🎉 SUCCESS: APP UPDATED AND COMPILED SECURELY!");
          updateStatus.log.push("Please refresh your browser to load the new code.");
          updateStatus.log.push("If server-side files (like server.js/ts) were changed,");
          updateStatus.log.push("manually restart the server in your command prompt.");
          updateStatus.log.push("=================================================");

          // Clean up updates directory
          try {
            fs.rmSync(DIR_UPDATES, { recursive: true, force: true });
            fs.mkdirSync(DIR_UPDATES, { recursive: true });
          } catch (e) {}
        }
      });

      return res.json({ success: true, message: "Update applying & compilation started in background." });
    } catch (err: any) {
      updateStatus.stage = "failed";
      updateStatus.error = err.message;
      updateStatus.log.push(`Error starting update: ${err.message}`);
      return res.status(500).json({ error: err.message });
    }
  });

  // Rollback/Undo the last applied update
  app.post("/api/admin/updates/rollback", (req, res) => {
    try {
      if (updateStatus.stage === "applying" || updateStatus.stage === "building") {
        return res.status(400).json({ error: "An update or compilation process is already running." });
      }

      const DIR_BACKUPS = path.join(process.cwd(), 'backups');
      const rollbackManifestPath = path.join(DIR_BACKUPS, 'rollback_manifest.json');
      const rollbackZipPath = path.join(DIR_BACKUPS, 'rollback_latest.zip');

      if (!fs.existsSync(rollbackManifestPath)) {
        return res.status(400).json({ error: "No rollback history found. You can only undo the last applied update." });
      }

      const rollbackManifest = JSON.parse(fs.readFileSync(rollbackManifestPath, 'utf8'));

      updateStatus.stage = "applying";
      updateStatus.progress = 20;
      updateStatus.log = ["Initializing rollback procedure...", `Restoring system to previous state from manifest timestamp: ${rollbackManifest.timestamp}`];
      updateStatus.error = null;

      // 1. Delete files that were newly created in the update
      if (rollbackManifest.newFiles && Array.isArray(rollbackManifest.newFiles)) {
        for (const newFile of rollbackManifest.newFiles) {
          const targetPath = path.join(process.cwd(), newFile);
          if (fs.existsSync(targetPath)) {
            try {
              fs.unlinkSync(targetPath);
              updateStatus.log.push(`🗑️ Deleted newly added file: ${newFile}`);
            } catch (err: any) {
              updateStatus.log.push(`⚠️ Failed to delete newly added file ${newFile}: ${err.message}`);
            }
          }
        }
      }

      // 2. Extract original files from the rollback ZIP
      if (fs.existsSync(rollbackZipPath)) {
        try {
          const zip = new AdmZip(rollbackZipPath);
          zip.extractAllTo(process.cwd(), true);
          updateStatus.log.push(`✅ Restored original versions of ${rollbackManifest.originalFiles.length} files.`);
        } catch (err: any) {
          updateStatus.stage = "failed";
          updateStatus.error = err.message;
          updateStatus.log.push(`❌ Failed to extract rollback ZIP: ${err.message}`);
          return res.status(500).json({ error: "Failed to restore files: " + err.message });
        }
      }

      updateStatus.log.push("File restoration complete. Compiling previous build...");
      updateStatus.stage = "building";
      updateStatus.progress = 60;

      // Clean up the rollback files so they can't be run twice in a row
      try {
        fs.unlinkSync(rollbackManifestPath);
        if (fs.existsSync(rollbackZipPath)) {
          fs.unlinkSync(rollbackZipPath);
        }
      } catch (e) {}

      // Spawn build execution
      exec("npm run build", { cwd: process.cwd() }, (err, stdout, stderr) => {
        if (err) {
          console.error("Compilation failed during rollback build:", err);
          updateStatus.stage = "failed";
          updateStatus.error = err.message || "Compilation failed";
          updateStatus.log.push(`❌ Compilation Failed: ${err.message}`);
          if (stderr) updateStatus.log.push(stderr);
        } else {
          console.log("Rollback compilation succeeded!");
          updateStatus.stage = "completed";
          updateStatus.progress = 100;
          updateStatus.log.push("=================================================");
          updateStatus.log.push("🎉 SUCCESS: SYSTEM SUCCESSFULLY ROLLED BACK!");
          updateStatus.log.push("Please refresh your browser to reload the code.");
          updateStatus.log.push("=================================================");
        }
      });

      return res.json({ success: true, message: "Rollback process initialized in background." });
    } catch (err: any) {
      updateStatus.stage = "failed";
      updateStatus.error = err.message;
      updateStatus.log.push(`Error starting rollback: ${err.message}`);
      return res.status(500).json({ error: err.message });
    }
  });

  // ----------------------------------------------------
  // ROBUST SYSTEM BACKUP & RESTORE ROUTER
  // ----------------------------------------------------
  const DIR_BACKUPS = path.join(process.cwd(), 'backups');
  if (!fs.existsSync(DIR_BACKUPS)) {
    fs.mkdirSync(DIR_BACKUPS, { recursive: true });
  }

  // Helper to create a backup ZIP file
  function createBackupFile(isAuto: boolean = false): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${isAuto ? 'auto' : 'manual'}_backup_${timestamp}.zip`;
    const backupPath = path.join(DIR_BACKUPS, filename);

    const zip = new AdmZip();
    
    // Add database file if it exists
    const FILE_DB = path.join(process.cwd(), 'data', 'db.json');
    if (fs.existsSync(FILE_DB)) {
      zip.addLocalFile(FILE_DB, 'data'); // extracts into data/db.json
    }

    // Add dcrns folder if it exists
    const DIR_DCRNS = path.join(process.cwd(), 'data', 'dcrns');
    if (fs.existsSync(DIR_DCRNS)) {
      try {
        const files = fs.readdirSync(DIR_DCRNS);
        if (files.length > 0) {
          zip.addLocalFolder(DIR_DCRNS, 'data/dcrns');
        }
      } catch (e) {
        console.error("Error backing up dcrns folder:", e);
      }
    }

    // Add uploads folder if it exists
    const DIR_UPLOADS = path.join(process.cwd(), 'uploads');
    if (fs.existsSync(DIR_UPLOADS)) {
      try {
        const files = fs.readdirSync(DIR_UPLOADS);
        if (files.length > 0) {
          zip.addLocalFolder(DIR_UPLOADS, 'uploads');
        }
      } catch (e) {
        console.error("Error backing up uploads folder:", e);
      }
    }

    zip.writeZip(backupPath);
    return filename;
  }

  // Cleanup old backups to prevent disk overflow
  function cleanupOldBackups() {
    try {
      if (!fs.existsSync(DIR_BACKUPS)) return;
      const files = fs.readdirSync(DIR_BACKUPS);
      
      // Auto backups cleanup (keep last 7)
      const autoBackups = files
        .filter(f => f.startsWith('auto_'))
        .map(f => ({ name: f, time: fs.statSync(path.join(DIR_BACKUPS, f)).mtimeMs }))
        .sort((a, b) => b.time - a.time);

      if (autoBackups.length > 7) {
        const toDelete = autoBackups.slice(7);
        for (const item of toDelete) {
          try {
            fs.unlinkSync(path.join(DIR_BACKUPS, item.name));
            console.log(`🧹 Backups Auto-Cleanup: Removed old auto backup: ${item.name}`);
          } catch (e) {}
        }
      }

      // Manual backups cleanup (keep last 7)
      const manualBackups = files
        .filter(f => f.startsWith('manual_'))
        .map(f => ({ name: f, time: fs.statSync(path.join(DIR_BACKUPS, f)).mtimeMs }))
        .sort((a, b) => b.time - a.time);

      if (manualBackups.length > 7) {
        const toDelete = manualBackups.slice(7);
        for (const item of toDelete) {
          try {
            fs.unlinkSync(path.join(DIR_BACKUPS, item.name));
            console.log(`🧹 Backups Auto-Cleanup: Removed old manual backup: ${item.name}`);
          } catch (e) {}
        }
      }
    } catch (err) {
      console.error("Error cleaning up backups:", err);
    }
  }

  // Restore database and uploads from a backup ZIP file safely
  function restoreFromBackupFile(zipFilePath: string): void {
    const zip = new AdmZip(zipFilePath);
    const FILE_DB = path.join(process.cwd(), 'data', 'db.json');

    // Create safety rollback copy of database in memory
    let rollbackDb: string | null = null;
    if (fs.existsSync(FILE_DB)) {
      rollbackDb = fs.readFileSync(FILE_DB, 'utf-8');
    }

    try {
      // Extract with overwrite enabled
      zip.extractAllTo(process.cwd(), true);
      
      // Validate extracted db.json is healthy
      if (fs.existsSync(FILE_DB)) {
        const dbContent = fs.readFileSync(FILE_DB, 'utf-8');
        JSON.parse(dbContent); // triggers syntax error if corrupted
      }
      console.log(`✅ Restore from ${path.basename(zipFilePath)} succeeded and validated!`);
    } catch (err: any) {
      // Critical error rollback
      if (rollbackDb !== null) {
        fs.writeFileSync(FILE_DB, rollbackDb, 'utf-8');
      }
      throw new Error("Restoration rolled back: ZIP container structure invalid or database corrupted. " + err.message);
    }
  }

  // Get list of all available backups
  app.get("/api/admin/backups/list", (req, res) => {
    try {
      if (!fs.existsSync(DIR_BACKUPS)) {
        fs.mkdirSync(DIR_BACKUPS, { recursive: true });
      }
      const files = fs.readdirSync(DIR_BACKUPS);
      const backups = files
        .filter(f => f.endsWith('.zip'))
        .map(file => {
          const stats = fs.statSync(path.join(DIR_BACKUPS, file));
          return {
            filename: file,
            size: stats.size,
            createdAt: stats.mtime,
            type: file.startsWith('auto_') ? 'automatic' : 'manual'
          };
        })
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()); // newest first

      return res.json({ backups });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // Create on-demand manual backup
  app.post("/api/admin/backups/create", (req, res) => {
    try {
      const filename = createBackupFile(false);
      cleanupOldBackups();
      return res.json({ success: true, message: "Backup file created successfully.", filename });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // Download a specific backup file
  app.get("/api/admin/backups/download/:filename", (req, res) => {
    try {
      const { filename } = req.params;
      const safeFilename = path.basename(filename);
      const filePath = path.join(DIR_BACKUPS, safeFilename);

      if (!fs.existsSync(filePath)) {
        return res.status(404).send("Backup file not found.");
      }

      return res.download(filePath, safeFilename);
    } catch (err: any) {
      return res.status(500).send(err.message);
    }
  });

  // Restore from an existing local backup file
  app.post("/api/admin/backups/restore/:filename", (req, res) => {
    try {
      const { filename } = req.params;
      const safeFilename = path.basename(filename);
      const filePath = path.join(DIR_BACKUPS, safeFilename);

      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: "Backup file not found on the server." });
      }

      restoreFromBackupFile(filePath);
      return res.json({ success: true, message: `System state successfully restored to point: ${safeFilename}` });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // Upload and restore from a backup file sent from the browser
  app.post("/api/admin/backups/upload-restore", upload.any(), (req, res) => {
    try {
      if (req.files && Array.isArray(req.files) && req.files.length > 0) {
        const file = req.files[0];
        
        try {
          restoreFromBackupFile(file.path);
          // Clean up the uploaded file from /uploads so it doesn't leak or sit around
          try {
            fs.unlinkSync(file.path);
          } catch (e) {}
          return res.json({ success: true, message: "System state successfully restored from uploaded package." });
        } catch (restoreErr: any) {
          try {
            fs.unlinkSync(file.path);
          } catch (e) {}
          return res.status(500).json({ error: restoreErr.message });
        }
      }
      return res.status(400).json({ error: "No backup package file received." });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // Delete a specific backup file
  app.delete("/api/admin/backups/:filename", (req, res) => {
    try {
      const { filename } = req.params;
      const safeFilename = path.basename(filename);
      const filePath = path.join(DIR_BACKUPS, safeFilename);

      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        return res.json({ success: true, message: "Backup file deleted successfully from server storage." });
      }
      return res.status(404).json({ error: "Backup file not found on server." });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // Reset entire system state (clears all databases and files)
  app.post("/api/admin/system/reset", (req, res) => {
    try {
      console.log("⚠️ [System Reset] Initiating full system reset...");

      // 1. Reset db.json to empty shell
      const emptyDb = { users: [], documents: [], auditLogs: [], dcrnRequests: [], loginSessions: [], customLogo: null };
      fs.writeFileSync(FILE_DB, JSON.stringify(emptyDb, null, 2), 'utf-8');

      // 2. Clear all files in DIR_DCRNS
      if (fs.existsSync(DIR_DCRNS)) {
        const files = fs.readdirSync(DIR_DCRNS);
        for (const file of files) {
          try {
            fs.unlinkSync(path.join(DIR_DCRNS, file));
          } catch (e) {
            console.error(`[System Reset] Failed to delete DCRN file ${file}`, e);
          }
        }
      }

      // 3. Clear all files in DIR_UPLOADS
      if (fs.existsSync(DIR_UPLOADS)) {
        const files = fs.readdirSync(DIR_UPLOADS);
        for (const file of files) {
          try {
            fs.unlinkSync(path.join(DIR_UPLOADS, file));
          } catch (e) {
            console.error(`[System Reset] Failed to delete uploaded file ${file}`, e);
          }
        }
      }

      // 4. Reset Calibration & Validation database and clear split files
      const FILE_CALVAL_DB = path.join(DIR_DATA, 'calval_db.json');
      const emptyCalVal = { records: [], auditLogs: [] };
      fs.writeFileSync(FILE_CALVAL_DB, JSON.stringify(emptyCalVal, null, 2), 'utf-8');

      if (fs.existsSync(DIR_CALIBRATIONS)) {
        const files = fs.readdirSync(DIR_CALIBRATIONS);
        for (const file of files) {
          try {
            fs.unlinkSync(path.join(DIR_CALIBRATIONS, file));
          } catch (e) {
            console.error(`[System Reset] Failed to delete Calibration record file ${file}`, e);
          }
        }
      }

      console.log("✅ [System Reset] System reset successfully completed.");
      return res.json({ success: true, message: "System state has been successfully reset to a clean slate." });
    } catch (err: any) {
      console.error("❌ [System Reset] Failed to perform system reset:", err);
      return res.status(500).json({ error: err.message });
    }
  });

  // Reset ONLY Document Portal (QMS) state
  app.post("/api/admin/system/reset-documents", (req, res) => {
    try {
      console.log("⚠️ [System Reset] Initiating Document Portal reset...");

      // 1. Read existing DB to preserve users, loginSessions and logo
      let currentDb: any = { users: [], loginSessions: [], customLogo: null };
      if (fs.existsSync(FILE_DB)) {
        try {
          const content = fs.readFileSync(FILE_DB, 'utf-8');
          currentDb = JSON.parse(content);
        } catch (e) {
          console.error("Error parsing FILE_DB during documents reset", e);
        }
      }

      // 2. Reset document-specific fields
      currentDb.documents = [];
      currentDb.auditLogs = [];
      currentDb.dcrnRequests = [];
      fs.writeFileSync(FILE_DB, JSON.stringify(currentDb, null, 2), 'utf-8');

      // 3. Clear all files in DIR_DCRNS
      if (fs.existsSync(DIR_DCRNS)) {
        const files = fs.readdirSync(DIR_DCRNS);
        for (const file of files) {
          try {
            fs.unlinkSync(path.join(DIR_DCRNS, file));
          } catch (e) {
            console.error(`[System Reset] Failed to delete DCRN file ${file}`, e);
          }
        }
      }

      // 4. Clear QMS uploads from DIR_UPLOADS, skipping the "calval" subdirectory
      if (fs.existsSync(DIR_UPLOADS)) {
        const files = fs.readdirSync(DIR_UPLOADS);
        for (const file of files) {
          const filePath = path.join(DIR_UPLOADS, file);
          try {
            const stat = fs.statSync(filePath);
            if (stat.isFile()) {
              fs.unlinkSync(filePath);
            } else if (stat.isDirectory() && file !== 'calval') {
              fs.rmSync(filePath, { recursive: true, force: true });
            }
          } catch (e) {
            console.error(`[System Reset] Failed to clean ${file}`, e);
          }
        }
      }

      console.log("✅ [System Reset] Document Portal reset completed.");
      return res.json({ success: true, message: "Document Portal data (Documents, DCRNs, and QMS logs) has been successfully reset." });
    } catch (err: any) {
      console.error("❌ [System Reset] Failed to perform Document Portal reset:", err);
      return res.status(500).json({ error: err.message });
    }
  });

  // Reset ONLY Calibration & Validation state
  app.post("/api/admin/system/reset-calval", (req, res) => {
    try {
      console.log("⚠️ [System Reset] Initiating Calibration & Validation reset...");

      // 1. Reset calval_db.json
      const FILE_CALVAL_DB = path.join(DIR_DATA, 'calval_db.json');
      const emptyCalVal = { records: [], auditLogs: [] };
      fs.writeFileSync(FILE_CALVAL_DB, JSON.stringify(emptyCalVal, null, 2), 'utf-8');

      // 2. Reset equipment lists in db.jason, equipments_db.json, and equipments_db.jason
      const FILE_EQUIPMENTS_DB = path.join(DIR_DATA, 'equipments_db.json');
      const FILE_EQUIPMENTS_JASON = path.join(DIR_DATA, 'equipments_db.jason');
      const FILE_DB_JASON = path.join(DIR_DATA, 'db.jason');

      const DEFAULT_EQUIPMENTS = [
        { id: 'PMC-PD-E001', name: 'High-Pressure Steam Autoclave', department: 'PD', lastCalibrationDate: '2026/01/10', reviewDueDate: '2026/07/10', calibrationType: 'NABL', calibrationPoint: 'Temp: 121C/134C, Pressure: 15/30 psi' },
        { id: 'PMC-PD-E002', name: 'Fluid Bed Dryer Process Unit', department: 'PD', lastCalibrationDate: '2026/02/15', reviewDueDate: '2026/08/15', calibrationType: 'Non-NABL', calibrationPoint: 'Airflow Velocity, Inlet Temp: 40-80C' },
        { id: 'PMC-PD-E003', name: 'Tablet Compression Machine', department: 'PD', lastCalibrationDate: '2026/03/20', reviewDueDate: '2026/09/20', calibrationType: 'NABL', calibrationPoint: 'Compression Force, Turret Speed' },
        { id: 'PMC-QC-E001', name: 'High-Performance Liquid Chromatograph', department: 'QC', lastCalibrationDate: '2026/01/05', reviewDueDate: '2026/07/05', calibrationType: 'NABL', calibrationPoint: 'Flow Rate: 0.1-2.0 ml/min, Wavelength' },
        { id: 'PMC-QC-E002', name: 'UV-Vis Spectrophotometer', department: 'QC', lastCalibrationDate: '2026/02/12', reviewDueDate: '2026/08/12', calibrationType: 'NABL', calibrationPoint: 'Absorbance: 200-800 nm, Slit Width' },
        { id: 'PMC-QC-E003', name: 'Analytical Weighing Balance', department: 'QC', lastCalibrationDate: '2026/03/01', reviewDueDate: '2026/09/01', calibrationType: 'Non-NABL', calibrationPoint: 'Mass Weight verification: 1mg - 100g' },
        { id: 'PMC-ST-E001', name: 'Cold Storage Room Temperature Monitor', department: 'ST', lastCalibrationDate: '2026/01/18', reviewDueDate: '2026/07/18', calibrationType: 'NABL', calibrationPoint: 'Temp mapping 12-points: 2C to 8C' },
        { id: 'PMC-ST-E002', name: 'Humidity Controlled Warehouse Chamber', department: 'ST', lastCalibrationDate: '2026/02/22', reviewDueDate: '2026/08/22', calibrationType: 'Non-NABL', calibrationPoint: 'Temp: 15-25C, RH: 30-60%' },
        { id: 'PMC-PK-E001', name: 'Blister Packaging Machine Heater', department: 'PK', lastCalibrationDate: '2026/01/25', reviewDueDate: '2026/07/25', calibrationType: 'Non-NABL', calibrationPoint: 'Seal Temp: 100-200C' },
        { id: 'PMC-PK-E002', name: 'Carton Sealing Laser Barcode Scanner', department: 'PK', lastCalibrationDate: '2026/02/28', reviewDueDate: '2026/08/28', calibrationType: 'Non-NABL', calibrationPoint: 'Scan trigger rate, Laser frequency' },
        { id: 'PMC-DD-E001', name: 'Thermal Cycling Chamber', department: 'DD', lastCalibrationDate: '2026/01/30', reviewDueDate: '2026/07/30', calibrationType: 'NABL', calibrationPoint: 'Cyclic Ramp Rate, Temp: -40C to 150C' },
        { id: 'PMC-DD-E002', name: '3D Prototyping Stress Gauge', department: 'DD', lastCalibrationDate: '2026/02/10', reviewDueDate: '2026/08/10', calibrationType: 'NABL', calibrationPoint: 'Load range: 0-500 N, Deflection' },
        { id: 'PMC-QA-E001', name: 'Document Vault Ambient Logger', department: 'QA', lastCalibrationDate: '2026/01/02', reviewDueDate: '2026/07/02', calibrationType: 'NABL', calibrationPoint: 'Temp: 22C +/- 2C, Humidity: 45%' }
      ];

      fs.writeFileSync(FILE_DB_JASON, JSON.stringify(DEFAULT_EQUIPMENTS, null, 2), 'utf-8');
      fs.writeFileSync(FILE_EQUIPMENTS_DB, JSON.stringify(DEFAULT_EQUIPMENTS, null, 2), 'utf-8');
      fs.writeFileSync(FILE_EQUIPMENTS_JASON, JSON.stringify(DEFAULT_EQUIPMENTS, null, 2), 'utf-8');

      // 3. Clear split calibrations files
      if (fs.existsSync(DIR_CALIBRATIONS)) {
        const files = fs.readdirSync(DIR_CALIBRATIONS);
        for (const file of files) {
          try {
            fs.unlinkSync(path.join(DIR_CALIBRATIONS, file));
          } catch (e) {
            console.error(`[System Reset] Failed to delete Calibration record file ${file}`, e);
          }
        }
      }

      // 4. Clear calval uploaded files inside DIR_CALVAL_UPLOADS
      const DIR_CALVAL_UPLOADS = path.join(DIR_UPLOADS, 'calval');
      if (fs.existsSync(DIR_CALVAL_UPLOADS)) {
        const files = fs.readdirSync(DIR_CALVAL_UPLOADS);
        for (const file of files) {
          try {
            fs.unlinkSync(path.join(DIR_CALVAL_UPLOADS, file));
          } catch (e) {
            console.error(`[System Reset] Failed to delete Calibration upload ${file}`, e);
          }
        }
      }

      console.log("✅ [System Reset] Calibration & Validation reset completed.");
      return res.json({ success: true, message: "Calibration & Validation system (records, equipment registry, and logs) has been successfully reset." });
    } catch (err: any) {
      console.error("❌ [System Reset] Failed to perform Calibration & Validation reset:", err);
      return res.status(500).json({ error: err.message });
    }
  });

  // ----------------------------------------------------
  // CALIBRATION & VALIDATION ENTERPRISE WORKFLOWS
  // ----------------------------------------------------
  
  // Fetch calval data
  app.get("/api/calval/data", (req, res) => {
    try {
      const FILE_CALVAL_DB = path.join(DIR_DATA, 'calval_db.json');
      const FILE_EQUIPMENTS_DB = path.join(DIR_DATA, 'equipments_db.json');
      const FILE_EQUIPMENTS_JASON = path.join(DIR_DATA, 'equipments_db.jason');
      const FILE_DB_JASON = path.join(DIR_DATA, 'db.jason');

      const DEFAULT_EQUIPMENTS = [
        { id: 'PMC-PD-E001', name: 'High-Pressure Steam Autoclave', department: 'PD', lastCalibrationDate: '2026/01/10', reviewDueDate: '2026/07/10', calibrationType: 'NABL', calibrationPoint: 'Temp: 121C/134C, Pressure: 15/30 psi' },
        { id: 'PMC-PD-E002', name: 'Fluid Bed Dryer Process Unit', department: 'PD', lastCalibrationDate: '2026/02/15', reviewDueDate: '2026/08/15', calibrationType: 'Non-NABL', calibrationPoint: 'Airflow Velocity, Inlet Temp: 40-80C' },
        { id: 'PMC-PD-E003', name: 'Tablet Compression Machine', department: 'PD', lastCalibrationDate: '2026/03/20', reviewDueDate: '2026/09/20', calibrationType: 'NABL', calibrationPoint: 'Compression Force, Turret Speed' },
        { id: 'PMC-QC-E001', name: 'High-Performance Liquid Chromatograph', department: 'QC', lastCalibrationDate: '2026/01/05', reviewDueDate: '2026/07/05', calibrationType: 'NABL', calibrationPoint: 'Flow Rate: 0.1-2.0 ml/min, Wavelength' },
        { id: 'PMC-QC-E002', name: 'UV-Vis Spectrophotometer', department: 'QC', lastCalibrationDate: '2026/02/12', reviewDueDate: '2026/08/12', calibrationType: 'NABL', calibrationPoint: 'Absorbance: 200-800 nm, Slit Width' },
        { id: 'PMC-QC-E003', name: 'Analytical Weighing Balance', department: 'QC', lastCalibrationDate: '2026/03/01', reviewDueDate: '2026/09/01', calibrationType: 'Non-NABL', calibrationPoint: 'Mass Weight verification: 1mg - 100g' },
        { id: 'PMC-ST-E001', name: 'Cold Storage Room Temperature Monitor', department: 'ST', lastCalibrationDate: '2026/01/18', reviewDueDate: '2026/07/18', calibrationType: 'NABL', calibrationPoint: 'Temp mapping 12-points: 2C to 8C' },
        { id: 'PMC-ST-E002', name: 'Humidity Controlled Warehouse Chamber', department: 'ST', lastCalibrationDate: '2026/02/22', reviewDueDate: '2026/08/22', calibrationType: 'Non-NABL', calibrationPoint: 'Temp: 15-25C, RH: 30-60%' },
        { id: 'PMC-PK-E001', name: 'Blister Packaging Machine Heater', department: 'PK', lastCalibrationDate: '2026/01/25', reviewDueDate: '2026/07/25', calibrationType: 'Non-NABL', calibrationPoint: 'Seal Temp: 100-200C' },
        { id: 'PMC-PK-E002', name: 'Carton Sealing Laser Barcode Scanner', department: 'PK', lastCalibrationDate: '2026/02/28', reviewDueDate: '2026/08/28', calibrationType: 'Non-NABL', calibrationPoint: 'Scan trigger rate, Laser frequency' },
        { id: 'PMC-DD-E001', name: 'Thermal Cycling Chamber', department: 'DD', lastCalibrationDate: '2026/01/30', reviewDueDate: '2026/07/30', calibrationType: 'NABL', calibrationPoint: 'Cyclic Ramp Rate, Temp: -40C to 150C' },
        { id: 'PMC-DD-E002', name: '3D Prototyping Stress Gauge', department: 'DD', lastCalibrationDate: '2026/02/10', reviewDueDate: '2026/08/10', calibrationType: 'NABL', calibrationPoint: 'Load range: 0-500 N, Deflection' },
        { id: 'PMC-QA-E001', name: 'Document Vault Ambient Logger', department: 'QA', lastCalibrationDate: '2026/01/02', reviewDueDate: '2026/07/02', calibrationType: 'NABL', calibrationPoint: 'Temp: 22C +/- 2C, Humidity: 45%' }
      ];

      let equipmentsList = DEFAULT_EQUIPMENTS;
      if (fs.existsSync(FILE_DB_JASON)) {
        try {
          equipmentsList = JSON.parse(fs.readFileSync(FILE_DB_JASON, 'utf-8'));
        } catch (e) {
          console.error("Error reading db.jason", e);
        }
      } else if (fs.existsSync(FILE_EQUIPMENTS_DB)) {
        try {
          equipmentsList = JSON.parse(fs.readFileSync(FILE_EQUIPMENTS_DB, 'utf-8'));
        } catch (e) {
          console.error("Error reading equipments_db.json", e);
        }
      } else if (fs.existsSync(FILE_EQUIPMENTS_JASON)) {
        try {
          equipmentsList = JSON.parse(fs.readFileSync(FILE_EQUIPMENTS_JASON, 'utf-8'));
        } catch (e) {
          console.error("Error reading equipments_db.jason", e);
        }
      } else {
        fs.writeFileSync(FILE_DB_JASON, JSON.stringify(DEFAULT_EQUIPMENTS, null, 2), 'utf-8');
        fs.writeFileSync(FILE_EQUIPMENTS_DB, JSON.stringify(DEFAULT_EQUIPMENTS, null, 2), 'utf-8');
        fs.writeFileSync(FILE_EQUIPMENTS_JASON, JSON.stringify(DEFAULT_EQUIPMENTS, null, 2), 'utf-8');
      }

      // Load all calibration records from split files
      const calibrationRecords = loadCalibrationRecords();

      let auditLogs = [];
      if (fs.existsSync(FILE_CALVAL_DB)) {
        try {
          const content = fs.readFileSync(FILE_CALVAL_DB, 'utf-8');
          const parsed = JSON.parse(content);
          auditLogs = parsed.auditLogs || [];
        } catch (e) {
          console.error("Error parsing calval_db.json for auditLogs", e);
        }
      }

      return res.json({
        records: calibrationRecords,
        auditLogs: auditLogs,
        equipments: equipmentsList
      });
    } catch (err: any) {
      console.error("Error reading calval_db.json or equipments database", err);
      res.status(500).json({ error: "Failed to read Calibration/Validation database state" });
    }
  });

  // Save calval data with smart server-side merging to prevent concurrency issues / data loss
  app.post("/api/calval/sync", (req, res) => {
    try {
      const FILE_CALVAL_DB = path.join(DIR_DATA, 'calval_db.json');
      const FILE_EQUIPMENTS_DB = path.join(DIR_DATA, 'equipments_db.json');
      const FILE_EQUIPMENTS_JASON = path.join(DIR_DATA, 'equipments_db.jason');
      const FILE_DB_JASON = path.join(DIR_DATA, 'db.jason');
      const { records: incomingRecords, auditLogs: incomingLogs, equipments: incomingEquipments } = req.body;

      // 1. Read existing data
      const existingRecords = loadCalibrationRecords();
      let existingLogs: any[] = [];
      if (fs.existsSync(FILE_CALVAL_DB)) {
        try {
          const content = fs.readFileSync(FILE_CALVAL_DB, 'utf-8');
          const parsed = JSON.parse(content);
          existingLogs = parsed.auditLogs || [];
        } catch (e) {
          console.error("Error reading existing calval_db.json for merge", e);
        }
      }

      let existingEquipments: any[] = [];
      let targetFile = FILE_DB_JASON;
      if (fs.existsSync(FILE_DB_JASON)) {
        targetFile = FILE_DB_JASON;
      } else if (fs.existsSync(FILE_EQUIPMENTS_DB)) {
        targetFile = FILE_EQUIPMENTS_DB;
      } else if (fs.existsSync(FILE_EQUIPMENTS_JASON)) {
        targetFile = FILE_EQUIPMENTS_JASON;
      }
      if (fs.existsSync(targetFile)) {
        try {
          existingEquipments = JSON.parse(fs.readFileSync(targetFile, 'utf-8')) || [];
        } catch (e) {
          console.error("Error reading existing equipments for merge", e);
        }
      }

      // 2. Perform the Smart Merges
      
      // Equipments merging (keyed by id)
      const eqMap = new Map();
      existingEquipments.forEach((eq: any) => {
        if (eq && eq.id) eqMap.set(eq.id, eq);
      });
      if (incomingEquipments && Array.isArray(incomingEquipments)) {
        incomingEquipments.forEach((eq: any) => {
          if (eq && eq.id) {
            // Overwrite existing or insert new
            eqMap.set(eq.id, eq);
          }
        });
      }
      const mergedEquipments = Array.from(eqMap.values());

      // Records merging (keyed by id) and split storage save
      const recMap = new Map();
      if (incomingRecords && Array.isArray(incomingRecords)) {
        const incomingIds = new Set(incomingRecords.map((r: any) => r.id).filter(Boolean));
        existingRecords.forEach((rec: any) => {
          if (rec && rec.id) {
            if (!incomingIds.has(rec.id)) {
              // Delete the file for this record as it has been deleted by the user
              const recFilePath = path.join(DIR_CALIBRATIONS, `${rec.id}.json`);
              if (fs.existsSync(recFilePath)) {
                fs.unlinkSync(recFilePath);
              }
            } else {
              recMap.set(rec.id, rec);
            }
          }
        });

        incomingRecords.forEach((rec: any) => {
          if (rec && rec.id) {
            // Overwrite existing or insert new
            recMap.set(rec.id, rec);
            // Write each record to its split-file storage under DIR_CALIBRATIONS
            const recFilePath = path.join(DIR_CALIBRATIONS, `${rec.id}.json`);
            fs.writeFileSync(recFilePath, JSON.stringify(rec, null, 2), 'utf-8');
          }
        });
      } else {
        existingRecords.forEach((rec: any) => {
          if (rec && rec.id) recMap.set(rec.id, rec);
        });
      }
      const mergedRecords = Array.from(recMap.values());

      // Audit logs merging (keyed by id, sorted by timestamp desc)
      const logsMap = new Map();
      existingLogs.forEach((log: any) => {
        if (log && log.id) logsMap.set(log.id, log);
      });
      if (incomingLogs && Array.isArray(incomingLogs)) {
        incomingLogs.forEach((log: any) => {
          if (log && log.id) {
            logsMap.set(log.id, log);
          }
        });
      }
      const mergedLogs = Array.from(logsMap.values()).sort((a: any, b: any) => {
        return new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime();
      });

      // 3. Write back merged data
      const model = {
        records: [], // leave records array empty in calval_db.json to save space exactly like DCRNs
        auditLogs: mergedLogs,
        equipments: [] // separate the equipments from calval_db.json
      };

      if (incomingEquipments) {
        fs.writeFileSync(FILE_DB_JASON, JSON.stringify(mergedEquipments, null, 2), 'utf-8');
        fs.writeFileSync(FILE_EQUIPMENTS_DB, JSON.stringify(mergedEquipments, null, 2), 'utf-8');
        fs.writeFileSync(FILE_EQUIPMENTS_JASON, JSON.stringify(mergedEquipments, null, 2), 'utf-8');
      }

      fs.writeFileSync(FILE_CALVAL_DB, JSON.stringify(model, null, 2), 'utf-8');

      // Return newly merged data to ensure client stays perfectly synchronized
      res.json({
        success: true,
        records: mergedRecords,
        auditLogs: mergedLogs,
        equipments: mergedEquipments
      });
    } catch (err: any) {
      console.error("Error writing calval_db.json and equipments databases during smart sync merge", err);
      res.status(500).json({ error: "Failed to sync Calibration/Validation database state" });
    }
  });

  // CalVal isolated upload handler
  app.post("/api/calval/upload", upload.any(), (req, res) => {
    try {
      const DIR_CALVAL_UPLOADS = path.join(DIR_UPLOADS, 'calval');
      if (!fs.existsSync(DIR_CALVAL_UPLOADS)) {
        fs.mkdirSync(DIR_CALVAL_UPLOADS, { recursive: true });
      }

      if (req.files && Array.isArray(req.files) && req.files.length > 0) {
        const file = req.files[0];
        const cleanFileName = path.basename(file.originalname);
        const destinationPath = path.join(DIR_CALVAL_UPLOADS, cleanFileName);
        const fileSizeInKb = (file.size / 1024).toFixed(0);
        const fileSizeFormatted = `${fileSizeInKb} KB`;

        fs.copyFileSync(file.path, destinationPath);
        fs.unlinkSync(file.path);

        return res.json({
          success: true,
          filename: cleanFileName,
          fileName: cleanFileName,
          url: `/uploads/calval/${cleanFileName}`,
          fileSize: fileSizeFormatted
        });
      }

      const { fileName, base64Data } = req.body || {};
      if (fileName && base64Data) {
        const cleanFileName = path.basename(fileName);
        const destinationPath = path.join(DIR_CALVAL_UPLOADS, cleanFileName);
        const fileBuffer = Buffer.from(base64Data, 'base64');
        fs.writeFileSync(destinationPath, fileBuffer);
        const fileSizeInKb = (fileBuffer.length / 1024).toFixed(0);
        const fileSizeFormatted = `${fileSizeInKb} KB`;

        return res.json({
          success: true,
          filename: cleanFileName,
          fileName: cleanFileName,
          url: `/uploads/calval/${cleanFileName}`,
          fileSize: fileSizeFormatted
        });
      }

      return res.status(400).json({ error: "No file content received." });
    } catch (err: any) {
      console.error("Error in CalVal upload:", err);
      res.status(500).json({ error: err.message });
    }
  });

  // Serve uploaded Calibration/Validation files
  app.get('/uploads/calval/:filename', (req, res) => {
    try {
      const DIR_CALVAL_UPLOADS = path.join(DIR_UPLOADS, 'calval');
      const cleanFileName = path.basename(req.params.filename);
      const filePath = path.join(DIR_CALVAL_UPLOADS, cleanFileName);
      if (fs.existsSync(filePath)) {
        return res.download(filePath, cleanFileName);
      }
      return res.status(404).send('Calibration/Validation file not found');
    } catch (err: any) {
      return res.status(500).send(err.message);
    }
  });

  // Calval backup create
  app.post("/api/calval/backups/create", (req, res) => {
    try {
      const DIR_CALVAL_BACKUPS = path.join(DIR_DATA, 'calval_backups');
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `calval_backup_${timestamp}.zip`;
      const backupPath = path.join(DIR_CALVAL_BACKUPS, filename);

      const zip = new AdmZip();
      const FILE_CALVAL_DB = path.join(DIR_DATA, 'calval_db.json');
      if (fs.existsSync(FILE_CALVAL_DB)) {
        zip.addLocalFile(FILE_CALVAL_DB, 'data');
      }
      const FILE_EQUIPMENTS_DB = path.join(DIR_DATA, 'equipments_db.json');
      if (fs.existsSync(FILE_EQUIPMENTS_DB)) {
        zip.addLocalFile(FILE_EQUIPMENTS_DB, 'data');
      }
      const FILE_EQUIPMENTS_JASON = path.join(DIR_DATA, 'equipments_db.jason');
      if (fs.existsSync(FILE_EQUIPMENTS_JASON)) {
        zip.addLocalFile(FILE_EQUIPMENTS_JASON, 'data');
      }
      const FILE_DB_JASON = path.join(DIR_DATA, 'db.jason');
      if (fs.existsSync(FILE_DB_JASON)) {
        zip.addLocalFile(FILE_DB_JASON, 'data');
      }

      const DIR_CALVAL_UPLOADS = path.join(DIR_UPLOADS, 'calval');
      if (fs.existsSync(DIR_CALVAL_UPLOADS)) {
        try {
          const files = fs.readdirSync(DIR_CALVAL_UPLOADS);
          if (files.length > 0) {
            zip.addLocalFolder(DIR_CALVAL_UPLOADS, 'uploads/calval');
          }
        } catch (e) {
          console.error("Error backing up calval uploads:", e);
        }
      }

      if (fs.existsSync(DIR_CALIBRATIONS)) {
        try {
          const files = fs.readdirSync(DIR_CALIBRATIONS);
          if (files.length > 0) {
            zip.addLocalFolder(DIR_CALIBRATIONS, 'data/calibrations');
          }
        } catch (e) {
          console.error("Error backing up split calibrations:", e);
        }
      }

      zip.writeZip(backupPath);
      return res.json({ success: true, message: "Calibration/Validation backup created successfully.", filename });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // Calval backups list
  app.get("/api/calval/backups/list", (req, res) => {
    try {
      const DIR_CALVAL_BACKUPS = path.join(DIR_DATA, 'calval_backups');
      if (!fs.existsSync(DIR_CALVAL_BACKUPS)) {
        fs.mkdirSync(DIR_CALVAL_BACKUPS, { recursive: true });
      }
      const files = fs.readdirSync(DIR_CALVAL_BACKUPS);
      const backups = files
        .filter(f => f.endsWith('.zip'))
        .map(file => {
          const stats = fs.statSync(path.join(DIR_CALVAL_BACKUPS, file));
          return {
            filename: file,
            size: stats.size,
            createdAt: stats.mtime,
            type: 'manual'
          };
        })
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

      return res.json({ backups });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // Calval download backup
  app.get("/api/calval/backups/download/:filename", (req, res) => {
    try {
      const DIR_CALVAL_BACKUPS = path.join(DIR_DATA, 'calval_backups');
      const { filename } = req.params;
      const safeFilename = path.basename(filename);
      const filePath = path.join(DIR_CALVAL_BACKUPS, safeFilename);

      if (!fs.existsSync(filePath)) {
        return res.status(404).send("Backup file not found.");
      }
      return res.download(filePath, safeFilename);
    } catch (err: any) {
      return res.status(500).send(err.message);
    }
  });

  // Calval backup delete
  app.delete("/api/calval/backups/:filename", (req, res) => {
    try {
      const DIR_CALVAL_BACKUPS = path.join(DIR_DATA, 'calval_backups');
      const { filename } = req.params;
      const safeFilename = path.basename(filename);
      const filePath = path.join(DIR_CALVAL_BACKUPS, safeFilename);

      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        return res.json({ success: true, message: "Backup deleted successfully." });
      }
      return res.status(404).json({ error: "Backup file not found." });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // Calval restore backup
  app.post("/api/calval/backups/restore/:filename", (req, res) => {
    try {
      const DIR_CALVAL_BACKUPS = path.join(DIR_DATA, 'calval_backups');
      const { filename } = req.params;
      const safeFilename = path.basename(filename);
      const filePath = path.join(DIR_CALVAL_BACKUPS, safeFilename);

      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: "Backup file not found on the server." });
      }

      // Clear current calibrations before extracting
      if (fs.existsSync(DIR_CALIBRATIONS)) {
        const files = fs.readdirSync(DIR_CALIBRATIONS);
        for (const file of files) {
          try {
            fs.unlinkSync(path.join(DIR_CALIBRATIONS, file));
          } catch (e) {}
        }
      }

      const zip = new AdmZip(filePath);
      zip.extractAllTo(process.cwd(), true);

      return res.json({ success: true, message: `Calibration/Validation system state successfully restored to: ${safeFilename}` });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // Calval upload & restore backup
  app.post("/api/calval/backups/upload-restore", upload.any(), (req, res) => {
    try {
      if (req.files && Array.isArray(req.files) && req.files.length > 0) {
        const file = req.files[0];
        try {
          // Clear current calibrations before extracting
          if (fs.existsSync(DIR_CALIBRATIONS)) {
            const files = fs.readdirSync(DIR_CALIBRATIONS);
            for (const file of files) {
              try {
                fs.unlinkSync(path.join(DIR_CALIBRATIONS, file));
              } catch (e) {}
            }
          }

          const zip = new AdmZip(file.path);
          zip.extractAllTo(process.cwd(), true);
          try {
            fs.unlinkSync(file.path);
          } catch (e) {}
          return res.json({ success: true, message: "Calibration/Validation system successfully restored from uploaded backup package." });
        } catch (restoreErr: any) {
          try {
            fs.unlinkSync(file.path);
          } catch (e) {}
          return res.status(500).json({ error: restoreErr.message });
        }
      }
      return res.status(400).json({ error: "No backup package file received." });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // Automatic scheduler background thread (triggers check on boot and every 1 hour)
  const twentyFourHours = 24 * 60 * 60 * 1000;
  
  const runAutoBackupCheck = () => {
    try {
      if (!fs.existsSync(DIR_BACKUPS)) {
        fs.mkdirSync(DIR_BACKUPS, { recursive: true });
      }
      const files = fs.readdirSync(DIR_BACKUPS);
      const autoFiles = files.filter(f => f.startsWith('auto_'));
      
      let latestAutoTime = 0;
      for (const file of autoFiles) {
        try {
          const stats = fs.statSync(path.join(DIR_BACKUPS, file));
          if (stats.mtimeMs > latestAutoTime) {
            latestAutoTime = stats.mtimeMs;
          }
        } catch (e) {}
      }

      if (Date.now() - latestAutoTime >= twentyFourHours) {
        console.log("⏰ Auto-Scheduler: Daily backup trigger point reached. Generating automated rolling backup...");
        const filename = createBackupFile(true);
        cleanupOldBackups();
        console.log(`✅ Auto-Scheduler: Daily backup successfully created: ${filename}`);
      }
    } catch (schedErr) {
      console.error("❌ Daily Backup Scheduler Engine Error:", schedErr);
    }
  };

  // Run initial boot check right away in 5 seconds
  setTimeout(runAutoBackupCheck, 5000);
  // Run periodic hourly check
  setInterval(runAutoBackupCheck, 60 * 60 * 1000);

  // ----------------------------------------------------
  // VITE CLIENT DEV MIDDLEWARE & PRODUCTION INDEX ROUTING
  // ----------------------------------------------------
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { 
        middlewareMode: true,
        watch: {
          ignored: [
            /node_modules/,
            /dist/,
            /dist-server/,
            /[\/\\]data[\/\\]/,
            /[\/\\]uploads[\/\\]/
          ]
        }
      },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // Bind to network interface
  if (useHttps && httpsOptions) {
    const secureServer = https.createServer(httpsOptions, app);
    
    const tryListen = (port: number) => {
      secureServer.listen(port, "0.0.0.0");
    };

    secureServer.on("listening", () => {
      const addr = secureServer.address();
      const actualPort = typeof addr === "string" ? addr : (addr?.port || 443);
      
      // Get all local non-internal IPv4 addresses
      const networkInterfaces = os.networkInterfaces();
      const lanIPs: string[] = [];
      for (const interfaceName of Object.keys(networkInterfaces)) {
        const interfaces = networkInterfaces[interfaceName];
        if (interfaces) {
          for (const ip of interfaces) {
            if (ip.family === "IPv4" && !ip.internal) {
              lanIPs.push(ip.address);
            }
          }
        }
      }

      console.log(`=======================================================`);
      console.log(`  eQMS OFFLINE LAN OFFICE SERVER SECURED (HTTPS)       `);
      console.log(`  Secure Local Access:  https://localhost:${actualPort}`);
      if (lanIPs.length > 0) {
        console.log(`  Secure LAN Access Links:`);
        lanIPs.forEach(ip => {
          console.log(`   👉  https://${ip}:${actualPort}`);
        });
      } else {
        console.log(`  Secure LAN Broadcaster: https://0.0.0.0:${actualPort}`);
      }
      console.log(`=======================================================`);
    });

    secureServer.on("error", (err: any) => {
      if (err.code === "EACCES") {
        console.warn(`⚠️ EACCES: Permission denied for port 443. Retrying on secure port 8443...`);
        tryListen(8443);
      } else {
        console.error(`❌ Secure HTTPS server error:`, err.message);
      }
    });

    tryListen(443);
  } else {
    app.listen(PORT, "0.0.0.0", () => {
      const networkInterfaces = os.networkInterfaces();
      const lanIPs: string[] = [];
      for (const interfaceName of Object.keys(networkInterfaces)) {
        const interfaces = networkInterfaces[interfaceName];
        if (interfaces) {
          for (const ip of interfaces) {
            if (ip.family === "IPv4" && !ip.internal) {
              lanIPs.push(ip.address);
            }
          }
        }
      }

      console.log(`=======================================================`);
      console.log(`  eQMS OFFLINE LAN OFFICE SERVER RUNNING SUCCESSFULLY  `);
      console.log(`  Local Access:  http://localhost:${PORT}`);
      if (lanIPs.length > 0) {
        console.log(`  LAN Access Links:`);
        lanIPs.forEach(ip => {
          console.log(`   👉  http://${ip}:${PORT}`);
        });
      } else {
        console.log(`  LAN IP Broadcaster: http://0.0.0.0:${PORT}`);
      }
      console.log(`=======================================================`);
    });
  }
}

startServer();
