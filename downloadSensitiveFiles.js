const axios = require('axios');
const fs = require('fs');
const path = require('path');

const reportFileName = 'security_report.json'; 

async function loadReport() {
  try {
    const data = fs.readFileSync(reportFileName, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Erreur lors du chargement du fichier JSON:', error.message);
    process.exit(1);
  }
}

async function downloadFile(url, savePath) {
  try {
    const response = await axios.get(url, { responseType: 'stream' });
    response.data.pipe(fs.createWriteStream(savePath));
  } catch (error) {
    console.error(`Erreur lors du téléchargement du fichier ${url}:`, error.message);
  }
}

async function downloadSensitiveFiles() {
  const report = await loadReport();

  if (!report.sensitiveFiles || report.sensitiveFiles.length === 0) {
    console.log('Aucun fichier sensible trouvé dans le rapport.');
    return;
  }

  const downloadDir = 'sensitive_files_downloads';
  if (!fs.existsSync(downloadDir)) {
    fs.mkdirSync(downloadDir);
  }

  await Promise.all(report.sensitiveFiles.map(async (fileUrl) => {
    const fileName = path.basename(fileUrl); 
    const savePath = path.join(downloadDir, fileName);
    await downloadFile(fileUrl, savePath);
  }));
}

downloadSensitiveFiles();
