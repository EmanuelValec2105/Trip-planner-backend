require('dotenv').config();
console.log("Client ID:", process.env.AMADEUS_CLIENT_ID);
console.log("Client Secret:", process.env.AMADEUS_CLIENT_SECRET);

const express = require('express');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

const SECRET_KEY = 'tajna123';

let refreshTokens = [];
let folders = [];

// Ucitvanje foldera
if (fs.existsSync('./folders.json')) {
  const data = fs.readFileSync('./folders.json', 'utf-8');
  folders = JSON.parse(data);
  console.log(`Učitano ${folders.length} foldera iz folders.json`);
}

// Azuriranje foldera
function saveFolders() {
  fs.writeFileSync('./folders.json', JSON.stringify(folders, null, 2));
  console.log('folders.json ažuriran.');
}

// Pocetna
app.get('/', (req, res) => {
  res.send('Trip Planner backend zadatak za intervju');
});

// Login
app.post('/login', (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).send('Username je obavezan.');
  }
  const accessToken = jwt.sign({ username }, SECRET_KEY, { expiresIn: '30m' });
  const refreshToken = jwt.sign({ username }, SECRET_KEY);
  refreshTokens.push(refreshToken);
  res.json({ accessToken, refreshToken });
});

// Refresh token
app.post('/token', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(401).send('Refresh token je obavezan.');
  }
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).send('Refresh token nije validan.');
  }
  jwt.verify(refreshToken, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).send('Token nije validan.');
    const accessToken = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '30m' });
    res.json({ accessToken });
  });
});

// Autentikacija tokena
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Dohvat letova s parametrima
app.get('/flights', authenticateToken, async (req, res) => {
  const { origin, destination, departureDate, adults, max } = req.query;
  if (!origin || !destination || !departureDate) {
    return res.status(400).send('Origin, destination i departureDate su obavezni.');
  }

  try {
    const tokenResponse = await fetch('https://test.api.amadeus.com/v1/security/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: process.env.AMADEUS_CLIENT_ID,
        client_secret: process.env.AMADEUS_CLIENT_SECRET
      })
    });
    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    const url = new URL('https://test.api.amadeus.com/v2/shopping/flight-offers');
    url.searchParams.append('originLocationCode', origin);
    url.searchParams.append('destinationLocationCode', destination);
    url.searchParams.append('departureDate', departureDate);
    url.searchParams.append('adults', adults || '1');
    url.searchParams.append('max', max || '3');

    const flightResponse = await fetch(url.toString(), {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    const flights = await flightResponse.json();
    res.json(flights);
  } catch (err) {
    console.error("Greška:", err);
    res.status(500).send('Greška pri dohvaćanju letova');
  }
});

// Kreiranje foldera
app.post('/folders', authenticateToken, (req, res) => {
  const { name } = req.body;
  if (!name) {
    return res.status(400).send('Naziv foldera je obavezan.');
  }

  const folder = {
    id: uuidv4(),
    name,
    owner: req.user.username,
    trips: [],
    sharedWith: []
  };

  folders.push(folder);
  saveFolders();
  res.json(folder);
});

// Dodavanje leta u folder
app.post('/folders/:folderId/trips', authenticateToken, (req, res) => {
  const { folderId } = req.params;
  const { flightData } = req.body;

  const folder = folders.find(f => f.id === folderId);
  if (!folder) return res.status(404).send('Folder nije pronađen.');

  if (folder.owner !== req.user.username && !folder.sharedWith.includes(req.user.username)) {
    return res.status(403).send('Nemate prava na ovaj folder.');
  }

  const trip = {
    id: uuidv4(),
    flightData
  };

  folder.trips.push(trip);
  saveFolders();
  res.json(trip);
});

// Dohvat foldera korisnika
app.get('/folders', authenticateToken, (req, res) => {
  const userFolders = folders.filter(f => 
    f.owner === req.user.username || f.sharedWith.includes(req.user.username)
  );
  res.json(userFolders);
});

// Dohvat detalja leta
app.get('/folders/:folderId/trips/:tripId', authenticateToken, (req, res) => {
  const { folderId, tripId } = req.params;

  const folder = folders.find(f => f.id === folderId);
  if (!folder) return res.status(404).send('Folder nije pronađen.');

  if (
    folder.owner !== req.user.username &&
    !folder.sharedWith.includes(req.user.username)
  ) {
    return res.status(403).send('Nemate prava za pregled ovog foldera.');
  }

  const trip = folder.trips.find(t => t.id === tripId);
  if (!trip) return res.status(404).send('Let nije pronađen.');

  res.json(trip);
});

// Rename foldera
app.put('/folders/:folderId', authenticateToken, (req, res) => {
  const { folderId } = req.params;
  const { name } = req.body;

  if (!name) return res.status(400).send('Novi naziv foldera je obavezan.');

  const folder = folders.find(f => f.id === folderId);
  if (!folder) return res.status(404).send('Folder nije pronađen.');

  if (
    folder.owner !== req.user.username &&
    !folder.sharedWith.includes(req.user.username)
  ) {
    return res.status(403).send('Nemate prava za uređivanje ovog foldera.');
  }

  folder.name = name;
  saveFolders();
  res.json(folder);
});

// Brisanje foldera (vlasnik)
app.delete('/folders/:folderId', authenticateToken, (req, res) => {
  const { folderId } = req.params;

  const folderIndex = folders.findIndex(f => f.id === folderId);
  if (folderIndex === -1) return res.status(404).send('Folder nije pronađen.');

  if (folders[folderIndex].owner !== req.user.username) {
    return res.status(403).send('Samo vlasnik može obrisati folder.');
  }

  folders.splice(folderIndex, 1);
  saveFolders();
  res.send('Folder je uspješno obrisan.');
});

// Brisanje leta iz foldera
app.delete('/folders/:folderId/trips/:tripId', authenticateToken, (req, res) => {
  const { folderId, tripId } = req.params;

  const folder = folders.find(f => f.id === folderId);
  if (!folder) return res.status(404).send('Folder nije pronađen.');

  if (
    folder.owner !== req.user.username &&
    !folder.sharedWith.includes(req.user.username)
  ) {
    return res.status(403).send('Nemate prava za brisanje letova.');
  }

  const tripIndex = folder.trips.findIndex(t => t.id === tripId);
  if (tripIndex === -1) return res.status(404).send('Let nije pronađen.');

  folder.trips.splice(tripIndex, 1);
  saveFolders();
  res.send('Let je obrisan.');
});

// Dijeljenje foldera
app.post('/folders/:folderId/share', authenticateToken, (req, res) => {
  const { folderId } = req.params;
  const { username } = req.body;

  if (!username) return res.status(400).send('Morate unijeti korisničko ime.');

  const folder = folders.find(f => f.id === folderId);
  if (!folder) return res.status(404).send('Folder nije pronađen.');

  if (folder.owner !== req.user.username) {
    return res.status(403).send('Samo vlasnik može dijeliti folder.');
  }

  if (folder.sharedWith.includes(username)) {
    return res.status(400).send('Korisnik već ima pristup folderu.');
  }

  folder.sharedWith.push(username);
  saveFolders();
  res.json(folder);
});

// Admin dohvat svih foldera
app.get('/all-folders', authenticateToken, (req, res) => {
  if (req.user.username !== 'admin') {
    return res.status(403).send('Samo admin može vidjeti sve foldere.');
  }
  res.json(folders);
});

// Admin brisanje foldera
app.delete('/admin/folders/:folderId', authenticateToken, (req, res) => {
  if (req.user.username !== 'admin') {
    return res.status(403).send('Samo admin može koristiti ovu rutu.');
  }

  const { folderId } = req.params;
  const folderIndex = folders.findIndex(f => f.id === folderId);
  if (folderIndex === -1) return res.status(404).send('Folder nije pronađen.');

  folders.splice(folderIndex, 1);
  saveFolders();
  res.send('Admin je obrisao folder.');
});

// Admin rename foldera
app.put('/admin/folders/:folderId', authenticateToken, (req, res) => {
  if (req.user.username !== 'admin') {
    return res.status(403).send('Samo admin može koristiti ovu rutu.');
  }

  const { folderId } = req.params;
  const { name } = req.body;
  if (!name) return res.status(400).send('Novi naziv foldera je obavezan.');

  const folder = folders.find(f => f.id === folderId);
  if (!folder) return res.status(404).send('Folder nije pronađen.');

  folder.name = name;
  saveFolders();
  res.json(folder);
});

// Admin brisanje leta
app.delete('/admin/folders/:folderId/trips/:tripId', authenticateToken, (req, res) => {
  if (req.user.username !== 'admin') {
    return res.status(403).send('Samo admin može koristiti ovu rutu.');
  }

  const { folderId, tripId } = req.params;
  const folder = folders.find(f => f.id === folderId);
  if (!folder) return res.status(404).send('Folder nije pronađen.');

  const tripIndex = folder.trips.findIndex(t => t.id === tripId);
  if (tripIndex === -1) return res.status(404).send('Let nije pronađen.');

  folder.trips.splice(tripIndex, 1);
  saveFolders();
  res.send('Admin je obrisao let.');
});

// Pokretanje servera
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server radi na portu ${PORT}`);
});
