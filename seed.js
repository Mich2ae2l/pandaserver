import { Low } from "lowdb";
import { JSONFile } from "lowdb/node";
import { nanoid } from "nanoid";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = new Low(new JSONFile(path.join(__dirname,"db.json")), { users: [], pdfs: [], transactions: [], downloadTokens: [] });
await db.read(); db.data ||= { users: [], pdfs: [], transactions: [], downloadTokens: [] };

const pdfPath = path.join(__dirname, "storage", "pdfs", "sample.pdf");
if (!fs.existsSync(pdfPath)){ fs.writeFileSync(pdfPath, Buffer.from("%PDF-1.4\n1 0 obj <<>> endobj\ntrailer <<>>\n%%EOF\n")); }

function add(state, year, title){ db.data.pdfs.push({ id:nanoid(), title, state, year, price_cents:899, status:"unsold", file_name:"sample.pdf", created_at: new Date().toISOString() }); }

if (!db.data.pdfs.length){
  add("GA",2003,"Georgia DMV Pack 2003");
  add("FL",2005,"Florida Tax Docs 2005");
  add("NC",2001,"North Carolina Academic Forms 2001");
  add("TX",2007,"Texas Insurance Bundle 2007");
  await db.write(); console.log("Seeded sample PDFs.");
} else {
  console.log("DB already has PDFs.");
}
