const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const dotenv = require("dotenv");
const { Pool } = require("pg");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;


// =========================================================
// DATABASE
// =========================================================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL
        ? { rejectUnauthorized: false }
        : false
});

async function query(text, params = []) {
    return pool.query(text, params);
}


async function initializeDatabase() {

    if (!process.env.DATABASE_URL) {

        console.warn(
            "DATABASE_URL ontbreekt. PostgreSQL is niet beschikbaar."
        );

        return;
    }

    await query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);


    await query(`
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);


    await query(`
        CREATE TABLE IF NOT EXISTS bikes (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            name TEXT NOT NULL,
            km DOUBLE PRECISION NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);


    await query(`
        CREATE TABLE IF NOT EXISTS parts (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            bike_id TEXT NOT NULL,
            name TEXT NOT NULL,
            price DOUBLE PRECISION NOT NULL DEFAULT 0,
            install_km DOUBLE PRECISION NOT NULL DEFAULT 0,
            interval_km DOUBLE PRECISION NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);


    await query(`
        CREATE TABLE IF NOT EXISTS maintenance (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            bike_id TEXT NOT NULL,
            type TEXT NOT NULL,
            date TEXT,
            km DOUBLE PRECISION NOT NULL DEFAULT 0,
            cost DOUBLE PRECISION NOT NULL DEFAULT 0,
            notes TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);


    await query(`
        CREATE TABLE IF NOT EXISTS strava_connections (
            user_id INTEGER PRIMARY KEY REFERENCES users(id)
                ON DELETE CASCADE,
            access_token TEXT NOT NULL,
            refresh_token TEXT NOT NULL,
            expires_at BIGINT,
            expires_in INTEGER,
            token_type TEXT,
            scope TEXT,
            athlete JSONB,
            sync_after BIGINT NOT NULL DEFAULT 0,
            initialized BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);


    await query(`
        CREATE TABLE IF NOT EXISTS strava_activities (
            user_id INTEGER NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            activity_id TEXT NOT NULL,
            activity JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (user_id, activity_id)
        );
    `);


    await query(`
        CREATE TABLE IF NOT EXISTS ride_assignments (
            user_id INTEGER NOT NULL REFERENCES users(id)
                ON DELETE CASCADE,
            activity_id TEXT NOT NULL,
            bike_id TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (user_id, activity_id)
        );
    `);


    console.log("PostgreSQL database is klaar.");
}


// =========================================================
// EXPRESS
// =========================================================

app.use(express.json({
    limit: "2mb"
}));

app.use(express.urlencoded({
    extended: true
}));

app.use(express.static(
    path.join(__dirname)
));


// =========================================================
// PASSWORDS
// =========================================================

function hashPassword(password) {

    return new Promise((resolve, reject) => {

        const salt =
            crypto.randomBytes(16).toString("hex");

        crypto.scrypt(
            password,
            salt,
            64,
            (error, derivedKey) => {

                if (error) {
                    reject(error);
                    return;
                }

                resolve(
                    salt +
                    ":" +
                    derivedKey.toString("hex")
                );
            }
        );
    });
}


function verifyPassword(password, storedHash) {

    return new Promise((resolve, reject) => {

        const parts =
            String(storedHash).split(":");

        if (parts.length !== 2) {
            resolve(false);
            return;
        }

        const salt = parts[0];
        const storedKey = parts[1];

        crypto.scrypt(
            password,
            salt,
            64,
            (error, derivedKey) => {

                if (error) {
                    reject(error);
                    return;
                }

                const derivedHex =
                    derivedKey.toString("hex");

                resolve(
                    crypto.timingSafeEqual(
                        Buffer.from(derivedHex),
                        Buffer.from(storedKey)
                    )
                );
            }
        );
    });
}


// =========================================================
// COOKIES
// =========================================================

function parseCookies(req) {

    const header =
        req.headers.cookie || "";

    const cookies = {};

    header
        .split(";")
        .map(item => item.trim())
        .filter(Boolean)
        .forEach(item => {

            const index =
                item.indexOf("=");

            if (index === -1) {
                return;
            }

            const key =
                item.slice(0, index);

            const value =
                item.slice(index + 1);

            cookies[key] =
                decodeURIComponent(value);
        });

    return cookies;
}


function setSessionCookie(res, sessionId) {

    res.setHeader(
        "Set-Cookie",
        [
            "bike_session=" +
            encodeURIComponent(sessionId),

            "Path=/",

            "HttpOnly",

            "SameSite=Lax",

            "Max-Age=2592000"
        ].join("; ")
    );
}


function clearSessionCookie(res) {

    res.setHeader(
        "Set-Cookie",
        "bike_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
    );
}


async function createSession(userId) {

    const sessionId =
        crypto.randomBytes(32).toString("hex");

    await query(
        `
        INSERT INTO sessions (
            id,
            user_id,
            expires_at
        )
        VALUES (
            $1,
            $2,
            NOW() + INTERVAL '30 days'
        )
        `,
        [
            sessionId,
            userId
        ]
    );

    return sessionId;
}


async function getCurrentUser(req) {

    const cookies =
        parseCookies(req);

    const sessionId =
        cookies.bike_session;

    if (!sessionId) {
        return null;
    }

    const result =
        await query(
            `
            SELECT
                users.id,
                users.email
            FROM sessions
            JOIN users
                ON users.id = sessions.user_id
            WHERE sessions.id = $1
              AND sessions.expires_at > NOW()
            `,
            [sessionId]
        );

    if (result.rows.length === 0) {
        return null;
    }

    return result.rows[0];
}


async function requireUser(req, res, next) {

    try {

        const user =
            await getCurrentUser(req);

        if (!user) {

            return res
                .status(401)
                .json({
                    error:
                        "Je moet ingelogd zijn."
                });
        }

        req.user =
            user;

        next();

    } catch (error) {

        console.error(
            "Authenticatie fout:",
            error
        );

        res
            .status(500)
            .json({
                error:
                    "Authenticatie kon niet worden gecontroleerd."
            });
    }
}


// =========================================================
// AUTHENTICATIE
// =========================================================

app.post(
    "/api/auth/register",
    async (req, res) => {

        try {

            const email =
                String(
                    req.body.email || ""
                )
                .trim()
                .toLowerCase();

            const password =
                String(
                    req.body.password || ""
                );


            if (!email || !password) {

                return res
                    .status(400)
                    .json({
                        error:
                            "E-mail en wachtwoord zijn verplicht."
                    });
            }


            if (password.length < 8) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Je wachtwoord moet minstens 8 tekens bevatten."
                    });
            }


            const existing =
                await query(
                    `
                    SELECT id
                    FROM users
                    WHERE email = $1
                    `,
                    [email]
                );


            if (existing.rows.length > 0) {

                return res
                    .status(409)
                    .json({
                        error:
                            "Er bestaat al een account met dit e-mailadres."
                    });
            }


            const passwordHash =
                await hashPassword(password);


            const result =
                await query(
                    `
                    INSERT INTO users (
                        email,
                        password_hash
                    )
                    VALUES (
                        $1,
                        $2
                    )
                    RETURNING id, email
                    `,
                    [
                        email,
                        passwordHash
                    ]
                );


            const user =
                result.rows[0];


            const sessionId =
                await createSession(
                    user.id
                );


            setSessionCookie(
                res,
                sessionId
            );


            res.json({
                success: true,
                user: {
                    id: user.id,
                    email: user.email
                }
            });

        } catch (error) {

            console.error(
                "Registratie fout:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Account aanmaken is mislukt."
                });
        }
    }
);


app.post(
    "/api/auth/login",
    async (req, res) => {

        try {

            const email =
                String(
                    req.body.email || ""
                )
                .trim()
                .toLowerCase();

            const password =
                String(
                    req.body.password || ""
                );


            const result =
                await query(
                    `
                    SELECT
                        id,
                        email,
                        password_hash
                    FROM users
                    WHERE email = $1
                    `,
                    [email]
                );


            if (result.rows.length === 0) {

                return res
                    .status(401)
                    .json({
                        error:
                            "E-mailadres of wachtwoord is niet juist."
                    });
            }


            const user =
                result.rows[0];


            const valid =
                await verifyPassword(
                    password,
                    user.password_hash
                );


            if (!valid) {

                return res
                    .status(401)
                    .json({
                        error:
                            "E-mailadres of wachtwoord is niet juist."
                    });
            }


            const sessionId =
                await createSession(
                    user.id
                );


            setSessionCookie(
                res,
                sessionId
            );


            res.json({
                success: true,
                user: {
                    id: user.id,
                    email: user.email
                }
            });

        } catch (error) {

            console.error(
                "Login fout:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Inloggen is mislukt."
                });
        }
    }
);


app.post(
    "/api/auth/logout",
    async (req, res) => {

        try {

            const cookies =
                parseCookies(req);

            const sessionId =
                cookies.bike_session;


            if (sessionId) {

                await query(
                    `
                    DELETE FROM sessions
                    WHERE id = $1
                    `,
                    [sessionId]
                );
            }


            clearSessionCookie(
                res
            );


            res.json({
                success: true
            });

        } catch (error) {

            console.error(
                "Logout fout:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Uitloggen is mislukt."
                });
        }
    }
);


app.get(
    "/api/auth/me",
    async (req, res) => {

        try {

            const user =
                await getCurrentUser(req);

            res.json({
                loggedIn:
                    Boolean(user),

                user:
                    user
                        ? {
                            id: user.id,
                            email: user.email
                        }
                        : null
            });

        } catch (error) {

            console.error(
                "Auth status fout:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Accountstatus kon niet worden opgehaald."
                });
        }
    }
);


// =========================================================
// FIETSEN
// =========================================================

app.get(
    "/api/data",
    requireUser,
    async (req, res) => {

        try {

            const userId =
                req.user.id;


            const bikes =
                await query(
                    `
                    SELECT
                        id,
                        name,
                        km
                    FROM bikes
                    WHERE user_id = $1
                    ORDER BY created_at ASC
                    `,
                    [userId]
                );


            const parts =
                await query(
                    `
                    SELECT
                        id,
                        bike_id,
                        name,
                        price,
                        install_km,
                        interval_km
                    FROM parts
                    WHERE user_id = $1
                    ORDER BY created_at ASC
                    `,
                    [userId]
                );


            const maintenance =
                await query(
                    `
                    SELECT
                        id,
                        bike_id,
                        type,
                        date,
                        km,
                        cost,
                        notes
                    FROM maintenance
                    WHERE user_id = $1
                    ORDER BY created_at ASC
                    `,
                    [userId]
                );


            const assignments =
                await query(
                    `
                    SELECT
                        activity_id,
                        bike_id
                    FROM ride_assignments
                    WHERE user_id = $1
                    `,
                    [userId]
                );


            res.json({

                bikes:
                    bikes.rows,

                parts:
                    parts.rows,

                maintenance:
                    maintenance.rows,

                rideAssignments:
                    Object.fromEntries(
                        assignments.rows.map(
                            item => [
                                String(item.activity_id),
                                item.bike_id
                            ]
                        )
                    )
            });

        } catch (error) {

            console.error(
                "Data ophalen fout:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Gegevens konden niet worden opgehaald."
                });
        }
    }
);


// =========================================================
// DATA OPSLAAN
// =========================================================

app.post(
    "/api/data",
    requireUser,
    async (req, res) => {

        const client =
            await pool.connect();

        try {

            const userId =
                req.user.id;

            const data =
                req.body || {};


            await client.query(
                "BEGIN"
            );


            await client.query(
                `
                DELETE FROM parts
                WHERE user_id = $1
                `,
                [userId]
            );


            await client.query(
                `
                DELETE FROM maintenance
                WHERE user_id = $1
                `,
                [userId]
            );


            await client.query(
                `
                DELETE FROM ride_assignments
                WHERE user_id = $1
                `,
                [userId]
            );


            await client.query(
                `
                DELETE FROM bikes
                WHERE user_id = $1
                `,
                [userId]
            );


            const bikes =
                Array.isArray(data.bikes)
                    ? data.bikes
                    : [];


            for (const bike of bikes) {

                await client.query(
                    `
                    INSERT INTO bikes (
                        id,
                        user_id,
                        name,
                        km
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4
                    )
                    `,
                    [
                        String(bike.id),
                        userId,
                        String(
                            bike.name || "Fiets"
                        ),
                        Number(
                            bike.km || 0
                        )
                    ]
                );
            }


            const parts =
                Array.isArray(data.parts)
                    ? data.parts
                    : [];


            for (const part of parts) {

                await client.query(
                    `
                    INSERT INTO parts (
                        id,
                        user_id,
                        bike_id,
                        name,
                        price,
                        install_km,
                        interval_km
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7
                    )
                    `,
                    [
                        String(part.id),
                        userId,
                        String(part.bikeId || ""),
                        String(
                            part.name || "Onderdeel"
                        ),
                        Number(
                            part.price || 0
                        ),
                        Number(
                            part.installKm ||
                            part.install_km ||
                            0
                        ),
                        Number(
                            part.intervalKm ||
                            part.interval_km ||
                            0
                        )
                    ]
                );
            }


            const maintenance =
                Array.isArray(data.maintenance)
                    ? data.maintenance
                    : [];


            for (const item of maintenance) {

                await client.query(
                    `
                    INSERT INTO maintenance (
                        id,
                        user_id,
                        bike_id,
                        type,
                        date,
                        km,
                        cost,
                        notes
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7,
                        $8
                    )
                    `,
                    [
                        String(item.id),
                        userId,
                        String(item.bikeId || ""),
                        String(
                            item.type || "Onderhoud"
                        ),
                        item.date || "",
                        Number(
                            item.km || 0
                        ),
                        Number(
                            item.cost || 0
                        ),
                        String(
                            item.notes || ""
                        )
                    ]
                );
            }


            const rideAssignments =
                data.rideAssignments &&
                typeof data.rideAssignments === "object"
                    ? data.rideAssignments
                    : {};


            for (
                const [activityId, bikeId]
                of Object.entries(
                    rideAssignments
                )
            ) {

                await client.query(
                    `
                    INSERT INTO ride_assignments (
                        user_id,
                        activity_id,
                        bike_id
                    )
                    VALUES (
                        $1,
                        $2,
                        $3
                    )
                    `,
                    [
                        userId,
                        String(activityId),
                        String(bikeId)
                    ]
                );
            }


            await client.query(
                "COMMIT"
            );


            res.json({
                success: true
            });

        } catch (error) {

            await client.query(
                "ROLLBACK"
            );


            console.error(
                "Data opslaan fout:",
                error
            );


            res
                .status(500)
                .json({
                    error:
                        "Gegevens konden niet worden opgeslagen."
                });

        } finally {

            client.release();
        }
    }
);


// =========================================================
// STRAVA CONFIGURATIE
// =========================================================

function isStravaConfigured() {

    return Boolean(
        process.env.STRAVA_CLIENT_ID &&
        process.env.STRAVA_CLIENT_SECRET
    );
}


function getStravaRedirectUri() {

    if (
        process.env.RENDER_EXTERNAL_URL
    ) {

        return (
            process.env.RENDER_EXTERNAL_URL
                .replace(/\/$/, "") +
            "/api/strava/callback"
        );
    }


    if (
        process.env.STRAVA_REDIRECT_URI
    ) {

        return process.env.STRAVA_REDIRECT_URI;
    }


    return (
        "http://localhost:" +
        PORT +
        "/api/strava/callback"
    );
}


// =========================================================
// STRAVA HELPERS
// =========================================================

async function getStravaConnection(userId) {

    const result =
        await query(
            `
            SELECT *
            FROM strava_connections
            WHERE user_id = $1
            `,
            [userId]
        );

    return (
        result.rows[0] ||
        null
    );
}


async function getValidAccessToken(
    userId
) {

    const connection =
        await getStravaConnection(
            userId
        );


    if (
        !connection ||
        !connection.refresh_token
    ) {

        return null;
    }


    const expiresAt =
        Number(
            connection.expires_at || 0
        );


    const now =
        Math.floor(
            Date.now() / 1000
        );


    if (
        connection.access_token &&
        expiresAt > now + 60
    ) {

        return connection.access_token;
    }


    console.log(
        "Strava access token verlopen. Vernieuwen..."
    );


    const response =
        await fetch(
            "https://www.strava.com/oauth/token",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({

                    client_id:
                        process.env.STRAVA_CLIENT_ID,

                    client_secret:
                        process.env.STRAVA_CLIENT_SECRET,

                    refresh_token:
                        connection.refresh_token,

                    grant_type:
                        "refresh_token"
                })
            }
        );


    const data =
        await response.json();


    if (!response.ok) {

        console.error(
            "Strava token refresh fout:",
            data
        );

        return null;
    }


    await query(
        `
        UPDATE strava_connections

        SET
            access_token = $1,
            refresh_token = $2,
            expires_at = $3,
            expires_in = $4,
            scope = $5,
            updated_at = NOW()

        WHERE user_id = $6
        `,
        [
            data.access_token,

            data.refresh_token ||
                connection.refresh_token,

            data.expires_at,

            data.expires_in,

            data.scope ||
                connection.scope,

            userId
        ]
    );


    console.log(
        "Strava access token vernieuwd."
    );


    return data.access_token;
}


// =========================================================
// STRAVA AUTH
// =========================================================

app.get(
    "/api/strava/auth",
    requireUser,
    (req, res) => {

        if (!isStravaConfigured()) {

            return res
                .status(500)
                .send(
                    "Strava is nog niet ingesteld."
                );
        }


        const redirectUri =
            getStravaRedirectUri();


        const state =
            crypto.randomBytes(32)
                .toString("hex");


        res.cookieState = state;


        res.setHeader(
            "Set-Cookie",
            [
                "strava_state=" +
                encodeURIComponent(state),

                "Path=/",

                "HttpOnly",

                "SameSite=Lax",

                "Max-Age=600"
            ].join("; ")
        );


        const params =
            new URLSearchParams({

                client_id:
                    process.env.STRAVA_CLIENT_ID,

                response_type:
                    "code",

                redirect_uri:
                    redirectUri,

                approval_prompt:
                    "auto",

                scope:
                    "read,activity:read",

                state:
                    state
            });


        res.redirect(
            "https://www.strava.com/oauth/authorize?" +
            params.toString()
        );
    }
);


// =========================================================
// STRAVA CALLBACK
// =========================================================

app.get(
    "/api/strava/callback",
    async (req, res) => {

        const code =
            req.query.code;

        const error =
            req.query.error;

        const state =
            req.query.state;


        if (error) {

            return res.send(`
                <!DOCTYPE html>

                <html lang="nl">

                <head>
                    <meta charset="UTF-8">
                    <title>Strava geannuleerd</title>
                </head>

                <body
                    style="
                        font-family: Arial;
                        padding: 40px;
                    "
                >

                    <h1>
                        Strava-koppeling geannuleerd
                    </h1>

                    <p>
                        Je hebt de koppeling geannuleerd.
                    </p>

                    <a href="/">
                        Terug naar Bike Maintenance
                    </a>

                </body>

                </html>
            `);
        }


        if (!code) {

            return res
                .status(400)
                .send(
                    "Geen Strava-code ontvangen."
                );
        }


        try {

            const cookies =
                parseCookies(req);


            const savedState =
                cookies.strava_state;


            if (
                !savedState ||
                !state ||
                savedState !== state
            ) {

                return res
                    .status(400)
                    .send(
                        "Ongeldige Strava-sessie."
                    );
            }


            const user =
                await getCurrentUser(req);


            if (!user) {

                return res
                    .status(401)
                    .send(
                        "Je moet eerst ingelogd zijn."
                    );
            }


            const response =
                await fetch(
                    "https://www.strava.com/oauth/token",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({

                            client_id:
                                process.env.STRAVA_CLIENT_ID,

                            client_secret:
                                process.env.STRAVA_CLIENT_SECRET,

                            code:
                                code,

                            grant_type:
                                "authorization_code"
                        })
                    }
                );


            const data =
                await response.json();


            if (!response.ok) {

                console.error(
                    "Strava OAuth fout:",
                    data
                );

                return res
                    .status(500)
                    .send(`
                        <h1>
                            Strava-koppeling mislukt
                        </h1>

                        <p>
                            Strava kon de koppeling niet voltooien.
                        </p>

                        <a href="/">
                            Terug naar Bike Maintenance
                        </a>
                    `);
            }


            await query(
                `
                INSERT INTO strava_connections (
                    user_id,
                    access_token,
                    refresh_token,
                    expires_at,
                    expires_in,
                    token_type,
                    scope,
                    athlete,
                    sync_after,
                    initialized
                )

                VALUES (
                    $1,
                    $2,
                    $3,
                    $4,
                    $5,
                    $6,
                    $7,
                    $8,
                    0,
                    FALSE
                )

                ON CONFLICT (user_id)

                DO UPDATE SET

                    access_token =
                        EXCLUDED.access_token,

                    refresh_token =
                        EXCLUDED.refresh_token,

                    expires_at =
                        EXCLUDED.expires_at,

                    expires_in =
                        EXCLUDED.expires_in,

                    token_type =
                        EXCLUDED.token_type,

                    scope =
                        EXCLUDED.scope,

                    athlete =
                        EXCLUDED.athlete,

                    sync_after =
                        0,

                    initialized =
                        FALSE,

                    updated_at =
                        NOW()
                `,
                [
                    user.id,

                    data.access_token,

                    data.refresh_token,

                    data.expires_at,

                    data.expires_in,

                    data.token_type,

                    data.scope || "",

                    data.athlete || null
                ]
            );


            res.setHeader(
                "Set-Cookie",
                "strava_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
            );


            console.log(
                "Strava succesvol gekoppeld aan gebruiker:",
                user.email
            );


            res.send(`
                <!DOCTYPE html>

                <html lang="nl">

                <head>

                    <meta charset="UTF-8">

                    <meta
                        http-equiv="refresh"
                        content="1;url=/"
                    >

                    <title>
                        Strava gekoppeld
                    </title>

                </head>

                <body
                    style="
                        font-family: Arial;
                        padding: 40px;
                        text-align: center;
                    "
                >

                    <h1>
                        🚴 Strava succesvol gekoppeld!
                    </h1>

                    <p>
                        Je wordt teruggestuurd naar Bike Maintenance.
                    </p>

                </body>

                </html>
            `);

        } catch (error) {

            console.error(
                "Strava callback fout:",
                error
            );

            res
                .status(500)
                .send(`
                    <h1>
                        Er ging iets mis
                    </h1>

                    <p>
                        Er kon geen verbinding met Strava worden gemaakt.
                    </p>

                    <a href="/">
                        Terug naar Bike Maintenance
                    </a>
                `);
        }
    }
);


// =========================================================
// STRAVA STATUS
// =========================================================

app.get(
    "/api/strava/status",
    requireUser,
    async (req, res) => {

        try {

            const connection =
                await getStravaConnection(
                    req.user.id
                );


            res.json({

                configured:
                    isStravaConfigured(),

                connected:
                    Boolean(
                        connection &&
                        connection.refresh_token
                    ),

                athlete:
                    connection
                        ? connection.athlete || null
                        : null
            });

        } catch (error) {

            console.error(
                "Strava status fout:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Strava-status kon niet worden opgehaald."
                });
        }
    }
);


// =========================================================
// STRAVA ACTIVITEITEN
// =========================================================

app.get(
    "/api/strava/activities",
    requireUser,
    async (req, res) => {

        try {

            const userId =
                req.user.id;


            const connection =
                await getStravaConnection(
                    userId
                );


            const accessToken =
                await getValidAccessToken(
                    userId
                );


            if (!connection || !accessToken) {

                return res
                    .status(401)
                    .json({
                        error:
                            "Strava is niet verbonden."
                    });
            }


            let after =
                Number(
                    connection.sync_after || 0
                );


            if (!connection.initialized) {

                after =
                    Math.floor(
                        (
                            Date.now() -
                            7 *
                            24 *
                            60 *
                            60 *
                            1000
                        ) / 1000
                    );

                console.log(
                    "Eerste synchronisatie voor gebruiker:",
                    req.user.email
                );
            }


            const url =
                "https://www.strava.com/api/v3/athlete/activities" +
                "?after=" +
                after +
                "&per_page=200";


            const response =
                await fetch(
                    url,
                    {
                        headers: {
                            Authorization:
                                "Bearer " +
                                accessToken
                        }
                    }
                );


            const data =
                await response.json();


            if (!response.ok) {

                console.error(
                    "Strava activiteiten fout:",
                    data
                );

                return res
                    .status(
                        response.status
                    )
                    .json({
                        error:
                            "Strava kon de activiteiten niet ophalen.",
                        details:
                            data
                    });
            }


            const newActivities = [];


            for (
                const activity of data
            ) {

                if (
                    !activity ||
                    !activity.id
                ) {
                    continue;
                }


                const sportType =
                    String(
                        activity.sport_type ||
                        activity.type ||
                        ""
                    ).toLowerCase();


                const isRide =
                    sportType.includes(
                        "ride"
                    ) ||
                    sportType.includes(
                        "cycling"
                    );


                if (!isRide) {
                    continue;
                }


                const exists =
                    await query(
                        `
                        SELECT 1
                        FROM strava_activities
                        WHERE user_id = $1
                          AND activity_id = $2
                        `,
                        [
                            userId,
                            String(
                                activity.id
                            )
                        ]
                    );


                if (
                    exists.rows.length > 0
                ) {
                    continue;
                }


                await query(
                    `
                    INSERT INTO strava_activities (
                        user_id,
                        activity_id,
                        activity
                    )
                    VALUES (
                        $1,
                        $2,
                        $3
                    )
                    ON CONFLICT DO NOTHING
                    `,
                    [
                        userId,

                        String(
                            activity.id
                        ),

                        activity
                    ]
                );


                newActivities.push(
                    activity
                );
            }


            let newestTimestamp =
                Number(
                    connection.sync_after ||
                    after
                );


            for (
                const activity of data
            ) {

                const dateString =
                    activity.start_date ||
                    activity.start_date_local;


                if (!dateString) {
                    continue;
                }


                const timestamp =
                    Math.floor(
                        new Date(
                            dateString
                        ).getTime() / 1000
                    );


                if (
                    Number.isFinite(
                        timestamp
                    ) &&
                    timestamp >
                        newestTimestamp
                ) {

                    newestTimestamp =
                        timestamp;
                }
            }


            await query(
                `
                UPDATE strava_connections

                SET
                    sync_after = $1,
                    initialized = TRUE,
                    updated_at = NOW()

                WHERE user_id = $2
                `,
                [
                    newestTimestamp,
                    userId
                ]
            );


            const stored =
                await query(
                    `
                    SELECT activity
                    FROM strava_activities
                    WHERE user_id = $1
                    ORDER BY
                        (activity->>'start_date') DESC
                    `,
                    [userId]
                );


            res.json({

                activities:
                    stored.rows.map(
                        row =>
                            row.activity
                    ),

                newActivities:
                    newActivities.length,

                synchronizedAt:
                    new Date().toISOString()
            });

        } catch (error) {

            console.error(
                "Strava synchronisatie fout:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Er ging iets mis tijdens de Strava-synchronisatie."
                });
        }
    }
);


// =========================================================
// STRAVA ONTKOPPELEN
// =========================================================

app.post(
    "/api/strava/disconnect",
    requireUser,
    async (req, res) => {

        try {

            const connection =
                await getStravaConnection(
                    req.user.id
                );


            if (
                connection &&
                connection.access_token
            ) {

                try {

                    await fetch(
                        "https://www.strava.com/oauth/deauthorize",
                        {
                            method: "POST",

                            headers: {
                                Authorization:
                                    "Bearer " +
                                    connection.access_token
                            }
                        }
                    );

                } catch (error) {

                    console.error(
                        "Strava deauthorize fout:",
                        error
                    );
                }
            }


            await query(
                `
                DELETE FROM strava_connections
                WHERE user_id = $1
                `,
                [req.user.id]
            );


            await query(
                `
                DELETE FROM strava_activities
                WHERE user_id = $1
                `,
                [req.user.id]
            );


            res.json({
                success: true
            });

        } catch (error) {

            console.error(
                "Strava disconnect fout:",
                error
            );

            res
                .status(500)
                .json({
                    error:
                        "Strava kon niet worden ontkoppeld."
                });
        }
    }
);


// =========================================================
// STRAVA DEBUG
// =========================================================

app.get(
    "/api/strava/debug",
    (req, res) => {

        const redirectUri =
            getStravaRedirectUri();


        res.json({

            render:
                Boolean(
                    process.env.RENDER
                ),

            renderExternalUrl:
                process.env.RENDER_EXTERNAL_URL ||
                null,

            databaseConfigured:
                Boolean(
                    process.env.DATABASE_URL
                ),

            clientIdAanwezig:
                Boolean(
                    process.env.STRAVA_CLIENT_ID
                ),

            clientIdLengte:
                process.env.STRAVA_CLIENT_ID
                    ? process.env.STRAVA_CLIENT_ID.length
                    : 0,

            clientSecretAanwezig:
                Boolean(
                    process.env.STRAVA_CLIENT_SECRET
                ),

            clientSecretLengte:
                process.env.STRAVA_CLIENT_SECRET
                    ? process.env.STRAVA_CLIENT_SECRET.length
                    : 0,

            redirectUri:
                redirectUri,

            redirectUriBron:
                process.env.RENDER_EXTERNAL_URL
                    ? "RENDER_EXTERNAL_URL"
                    : process.env.STRAVA_REDIRECT_URI
                        ? "STRAVA_REDIRECT_URI"
                        : "localhost",

            stravaConfigured:
                isStravaConfigured()
        });

    }
);


// =========================================================
// TEST
// =========================================================

app.get(
    "/api/test",
    (req, res) => {

        res.json({

            status:
                "ok",

            message:
                "Bike Maintenance server werkt!"
        });

    }
);


// =========================================================
// DATABASE TEST
// =========================================================

app.get(
    "/api/database-test",
    async (req, res) => {

        try {

            const result =
                await query(
                    "SELECT NOW() AS time"
                );


            res.json({

                success:
                    true,

                message:
                    "PostgreSQL werkt!",

                time:
                    result.rows[0].time
            });

        } catch (error) {

            console.error(
                "Database test fout:",
                error
            );

            res
                .status(500)
                .json({

                    success:
                        false,

                    error:
                        "PostgreSQL verbinding mislukt."
                });
        }
    }
);


// =========================================================
// SERVER STARTEN
// =========================================================

async function startServer() {

    try {

        await initializeDatabase();


        app.listen(
            PORT,
            "0.0.0.0",
            () => {

                console.log(
                    "Bike Maintenance draait op poort " +
                    PORT
                );

                console.log(
                    "Strava ingesteld:",
                    isStravaConfigured()
                );

                console.log(
                    "Strava redirect URI:",
                    getStravaRedirectUri()
                );

                console.log(
                    "PostgreSQL ingesteld:",
                    Boolean(
                        process.env.DATABASE_URL
                    )
                );
            }
        );

    } catch (error) {

        console.error(
            "Server kon niet starten:",
            error
        );

        process.exit(1);
    }
}


startServer();