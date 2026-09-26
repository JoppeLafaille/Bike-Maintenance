const express = require("express");
const path = require("path");
const fs = require("fs");
const dotenv = require("dotenv");

dotenv.config();

const app = express();

const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------
// AUTOMATISCHE REDIRECT URI
// ---------------------------------------------------------
//
// Op Render gebruiken we automatisch de publieke Render-URL.
// Lokaal blijft STRAVA_REDIRECT_URI uit .env bruikbaar.
//

function getStravaRedirectUri() {
    if (process.env.RENDER_EXTERNAL_URL) {
        return (
            process.env.RENDER_EXTERNAL_URL.replace(/\/$/, "") +
            "/api/strava/callback"
        );
    }

    if (process.env.STRAVA_REDIRECT_URI) {
        return process.env.STRAVA_REDIRECT_URI;
    }

    return (
        "http://localhost:" +
        PORT +
        "/api/strava/callback"
    );
}

const TOKEN_FILE = path.join(
    __dirname,
    "strava-token.json"
);

const ACTIVITIES_FILE = path.join(
    __dirname,
    "strava-activities.json"
);

app.use(express.json());

app.use(
    express.static(
        path.join(__dirname)
    )
);


// ---------------------------------------------------------
// BESTANDSHELPERS
// ---------------------------------------------------------

function readJsonFile(file, fallback) {
    try {
        if (!fs.existsSync(file)) {
            return fallback;
        }

        const content =
            fs.readFileSync(
                file,
                "utf8"
            );

        if (!content.trim()) {
            return fallback;
        }

        return JSON.parse(content);

    } catch (error) {

        console.error(
            "Fout bij lezen van bestand:",
            file
        );

        console.error(error);

        return fallback;
    }
}


function writeJsonFile(file, data) {

    fs.writeFileSync(
        file,
        JSON.stringify(
            data,
            null,
            2
        ),
        "utf8"
    );

}


function getTokenData() {

    return readJsonFile(
        TOKEN_FILE,
        null
    );

}


function saveTokenData(data) {

    writeJsonFile(
        TOKEN_FILE,
        data
    );

}


function getStoredActivities() {

    return readJsonFile(
        ACTIVITIES_FILE,
        {
            initialized: false,
            syncAfter: null,
            activities: []
        }
    );

}


function saveStoredActivities(data) {

    writeJsonFile(
        ACTIVITIES_FILE,
        data
    );

}


// ---------------------------------------------------------
// STRAVA CONFIGURATIE
// ---------------------------------------------------------

function isStravaConfigured() {

    return Boolean(
        process.env.STRAVA_CLIENT_ID &&
        process.env.STRAVA_CLIENT_SECRET
    );

}


// ---------------------------------------------------------
// STRAVA ACCESS TOKEN
// ---------------------------------------------------------

async function getValidAccessToken() {

    const tokenData =
        getTokenData();

    if (
        !tokenData ||
        !tokenData.refresh_token
    ) {
        return null;
    }

    const expiresAt =
        Number(
            tokenData.expires_at || 0
        );

    const now =
        Math.floor(
            Date.now() / 1000
        );

    if (
        tokenData.access_token &&
        expiresAt > now + 60
    ) {

        return tokenData.access_token;

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
                        tokenData.refresh_token,

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

    const updatedTokenData = {

        ...tokenData,

        access_token:
            data.access_token,

        refresh_token:
            data.refresh_token ||
            tokenData.refresh_token,

        expires_at:
            data.expires_at,

        expires_in:
            data.expires_in,

        scope:
            data.scope ||
            tokenData.scope
    };

    saveTokenData(
        updatedTokenData
    );

    console.log(
        "Strava access token vernieuwd."
    );

    return updatedTokenData.access_token;
}


// ---------------------------------------------------------
// STRAVA LOGIN
// ---------------------------------------------------------

app.get(
    "/api/strava/auth",
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

        console.log(
            "Strava redirect URI:",
            redirectUri
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
                    "read,activity:read"
            });

        res.redirect(
            "https://www.strava.com/oauth/authorize?" +
            params.toString()
        );
    }
);


// ---------------------------------------------------------
// STRAVA CALLBACK
// ---------------------------------------------------------

app.get(
    "/api/strava/callback",
    async (req, res) => {

        const code =
            req.query.code;

        const error =
            req.query.error;

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
                        <!DOCTYPE html>

                        <html lang="nl">

                        <head>
                            <meta charset="UTF-8">
                            <title>Strava fout</title>
                        </head>

                        <body
                            style="
                                font-family: Arial;
                                padding: 40px;
                            "
                        >

                            <h1>
                                Strava-koppeling mislukt
                            </h1>

                            <p>
                                Strava kon de koppeling niet voltooien.
                            </p>

                            <a href="/">
                                Terug naar Bike Maintenance
                            </a>

                        </body>

                        </html>
                    `);
            }

            const tokenData = {

                access_token:
                    data.access_token,

                refresh_token:
                    data.refresh_token,

                expires_at:
                    data.expires_at,

                expires_in:
                    data.expires_in,

                token_type:
                    data.token_type,

                scope:
                    data.scope || "",

                athlete:
                    data.athlete || null
            };

            saveTokenData(
                tokenData
            );

            if (
                !fs.existsSync(
                    ACTIVITIES_FILE
                )
            ) {

                saveStoredActivities({
                    initialized: false,
                    syncAfter: null,
                    activities: []
                });

            }

            console.log(
                "Strava succesvol gekoppeld."
            );

            res.send(`
                <!DOCTYPE html>

                <html lang="nl">

                <head>

                    <meta charset="UTF-8">

                    <meta
                        http-equiv="refresh"
                        content="2;url=/"
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


// ---------------------------------------------------------
// STRAVA STATUS
// ---------------------------------------------------------

app.get(
    "/api/strava/status",
    (req, res) => {

        const tokenData =
            getTokenData();

        res.json({

            configured:
                isStravaConfigured(),

            connected:
                Boolean(
                    tokenData &&
                    tokenData.refresh_token
                ),

            athlete:
                tokenData
                    ? tokenData.athlete || null
                    : null
        });

    }
);


// ---------------------------------------------------------
// STRAVA ACTIVITEITEN
// ---------------------------------------------------------

app.get(
    "/api/strava/activities",
    async (req, res) => {

        try {

            const accessToken =
                await getValidAccessToken();

            if (!accessToken) {

                return res
                    .status(401)
                    .json({
                        error:
                            "Strava is niet verbonden."
                    });
            }

            const stored =
                getStoredActivities();

            let after;

            if (!stored.initialized) {

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
                    "Eerste synchronisatie: laatste 7 dagen."
                );

            } else {

                after =
                    Number(
                        stored.syncAfter || 0
                    );

                console.log(
                    "Nieuwe activiteiten ophalen vanaf:",
                    new Date(
                        after * 1000
                    ).toISOString()
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

            const existingIds =
                new Set(
                    stored.activities.map(
                        activity =>
                            String(
                                activity.id
                            )
                    )
                );

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

                if (
                    existingIds.has(
                        String(
                            activity.id
                        )
                    )
                ) {
                    continue;
                }

                newActivities.push(
                    activity
                );

                existingIds.add(
                    String(
                        activity.id
                    )
                );
            }

            if (
                newActivities.length > 0
            ) {

                stored.activities.push(
                    ...newActivities
                );

            }

            let newestTimestamp =
                Number(
                    stored.syncAfter ||
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

            stored.initialized =
                true;

            stored.syncAfter =
                newestTimestamp;

            stored.activities.sort(
                (a, b) =>
                    new Date(
                        b.start_date
                    ).getTime() -
                    new Date(
                        a.start_date
                    ).getTime()
            );

            saveStoredActivities(
                stored
            );

            console.log(
                "Nieuwe Strava-ritten:",
                newActivities.length
            );

            res.json({

                activities:
                    stored.activities,

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


// ---------------------------------------------------------
// STRAVA ONTKOPPELEN
// ---------------------------------------------------------

app.post(
    "/api/strava/disconnect",
    async (req, res) => {

        try {

            const tokenData =
                getTokenData();

            if (
                tokenData &&
                tokenData.access_token
            ) {

                try {

                    await fetch(
                        "https://www.strava.com/oauth/deauthorize",
                        {
                            method: "POST",

                            headers: {
                                Authorization:
                                    "Bearer " +
                                    tokenData.access_token
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

            if (
                fs.existsSync(
                    TOKEN_FILE
                )
            ) {

                fs.unlinkSync(
                    TOKEN_FILE
                );

            }

            if (
                fs.existsSync(
                    ACTIVITIES_FILE
                )
            ) {

                fs.unlinkSync(
                    ACTIVITIES_FILE
                );

            }

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


// ---------------------------------------------------------
// DEBUG
// ---------------------------------------------------------

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


// ---------------------------------------------------------
// TEST
// ---------------------------------------------------------

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


// ---------------------------------------------------------
// SERVER STARTEN
// ---------------------------------------------------------

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

    }
);