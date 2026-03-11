const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const rateLimiter = require('express-rate-limit');
const compression = require('compression');
const path = require('path');

app.use(express.static(path.join(__dirname, 'public')));
app.use(compression({
    level: 5,
    threshold: 0,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    }
}));
app.set('view engine', 'ejs');
app.set('trust proxy', 1);
app.use(function (req, res, next) {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    console.log(`[${new Date().toLocaleString()}] ${req.method} ${req.url} - ${res.statusCode}`);
    next();
});
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(rateLimiter({ windowMs: 5 * 60 * 1000, max: 800, headers: true }));

app.all('/favicon.ico', function(req, res) { res.end(); });

app.all('/player/register', function(req, res) {
    res.send("Coming soon...");
});

// ─────────────────────────────────────────────
// Dashboard — serve EJS login/register page
// ─────────────────────────────────────────────
app.all('/player/login/dashboard', function (req, res) {
    const tData = {};
    try {
        const uData = JSON.stringify(req.body).split('"')[1].split('\\n');
        for (let i = 0; i < uData.length - 1; i++) {
            const d = uData[i].split('|');
            tData[d[0]] = d[1];
        }
    } catch (why) {
        console.log(`Warning: ${why}`);
    }
    res.render(__dirname + '/public/html/dashboard.ejs', { data: tData });
});

// ─────────────────────────────────────────────
// Validate — login atau register
//
// FIX 1: url diisi checktoken URL supaya
//         Growtopia client hit checktoken
//         sebelum kirim ltoken ke C++ server
//
// FIX 2: token pakai email + reg=1 untuk
//         register, dan reg=0 untuk login
//         JANGAN diubah di checktoken!
// ─────────────────────────────────────────────
app.all('/player/growid/login/validate', (req, res) => {
    const _token   = req.body._token   || '';
    const growId   = req.body.growId   || '';
    const password = req.body.password || '';
    const email    = req.body.email    || '';

    let tokenData = '';
    if (email) {
        // REGISTER — ada email
        tokenData = `_token=${_token}&growId=${growId}&password=${password}&email=${email}&reg=1`;
        console.log(`[VALIDATE] REGISTER growId=${growId}`);
    } else {
        // LOGIN — tidak ada email
        tokenData = `_token=${_token}&growId=${growId}&password=${password}&reg=0`;
        console.log(`[VALIDATE] LOGIN growId=${growId}`);
    }

    const token = Buffer.from(tokenData).toString('base64');

    // GANTI domain ini dengan domain deploy kamu
    const BACKEND_DOMAIN = process.env.BACKEND_DOMAIN || req.headers.host || 'localhost:5000';

    res.send(JSON.stringify({
        status: 'success',
        message: 'Account Validated.',
        token: token,
        url: `https://${BACKEND_DOMAIN}/player/growid/checktoken|liner`,
        accountType: 'growtopia',
        accountAge: 2,
    }));
});

// ─────────────────────────────────────────────
// Checktoken step 1 — redirect ke step 2
// ─────────────────────────────────────────────
app.all('/player/growid/checktoken', async (req, res) => {
    return res.redirect(307, '/player/growid/validate/checktoken');
});

// ─────────────────────────────────────────────
// Checktoken step 2 — update _token saja
//
// FIX 3: JANGAN ubah atau hapus &reg=0/1
//         dan &email=... dari token!
//         C++ butuh email untuk deteksi
//         register vs login.
// ─────────────────────────────────────────────
app.all('/player/growid/validate/checktoken', async (req, res) => {
    try {
        const body = req.body;

        // Support berbagai format body
        let refreshToken = body?.refreshToken;
        let clientData   = body?.clientData;

        // Format: { data: { refreshToken, clientData } }
        if (!refreshToken && body?.data) {
            refreshToken = body.data.refreshToken;
            clientData   = body.data.clientData;
        }

        // Format: single key form payload
        if (!refreshToken && body && Object.keys(body).length === 1) {
            try {
                const raw = Object.keys(body)[0];
                const params = new URLSearchParams(raw);
                refreshToken = params.get('refreshToken') || undefined;
                clientData   = params.get('clientData')   || undefined;
            } catch(e) {}
        }

        console.log(`[CHECKTOKEN] refreshToken=${refreshToken ? 'OK' : 'MISSING'} clientData=${clientData ? 'OK' : 'MISSING'}`);

        if (!refreshToken || !clientData) {
            return res.status(200).json({
                status: 'error',
                message: 'Missing refreshToken or clientData',
            });
        }

        // Decode token lama
        const decoded = Buffer.from(refreshToken, 'base64').toString('utf-8');
        console.log(`[CHECKTOKEN] decoded: ${decoded}`);

        // FIX KRITIS: JANGAN hapus &reg atau &email!
        // Hanya ganti nilai _token dengan clientData baru
        // Semua field lain (growId, password, email, reg) TETAP UTUH
        const updated = decoded.replace(
            /(_token=)[^&]*/,
            `$1${Buffer.from(clientData).toString('base64')}`
        );

        const token = Buffer.from(updated).toString('base64');
        console.log(`[CHECKTOKEN] final: ${updated}`);

        res.send(JSON.stringify({
            status: 'success',
            message: 'Account Validated.',
            token: token,
            url: '',
            accountType: 'growtopia',
            accountAge: 2,
        }));
    } catch (error) {
        console.log(`[ERROR]: ${error}`);
        res.status(500).json({ status: 'error', message: 'Internal Server Error' });
    }
});

app.get('/', function (req, res) {
    res.send('Hello World!');
});

app.listen(5000, function () {
    console.log('Listening on port 5000');
});
