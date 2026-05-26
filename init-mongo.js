db = db.getSiblingDB('vulnerabilidades');

db.createCollection('cves');
db.createCollection('exploits');
db.createCollection('analisis');
db.createCollection('hallazgos');

db.cves.createIndex({ id: 1 }, { unique: true });
db.cves.createIndex({ severity: 1 });
db.cves.createIndex({ publishedDate: 1 });
db.cves.createIndex({ '$**': 'text' });

db.exploits.createIndex({ id: 1 }, { unique: true });
db.exploits.createIndex({ path: 1 });
db.exploits.createIndex({ '$**': 'text' });

db.analisis.createIndex({ projectPath: 1 });
db.analisis.createIndex({ timestamp: -1 });
db.analisis.createIndex({ estado: 1 });

db.hallazgos.createIndex({ analisisId: 1 });
db.hallazgos.createIndex({ severidad: 1 });

db.cves.createIndex({ chromaId: 1 });
db.exploits.createIndex({ chromaId: 1 });
