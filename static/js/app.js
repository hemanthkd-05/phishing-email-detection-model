// ===============================
// SIDEBAR NAVIGATION
// ===============================

document.addEventListener("DOMContentLoaded", () => {

    const navItems = document.querySelectorAll(".nav-item");

    navItems.forEach(item => {

        item.addEventListener("click", function (event) {

            event.preventDefault();

            // Remove active from all buttons
            navItems.forEach(nav => {
                nav.classList.remove("active");
            });

            // Add active to clicked button
            this.classList.add("active");

            // Get target section
            const target = this.getAttribute("href");

            // Dashboard
            if (target === "#") {
                window.scrollTo({
                    top: 0,
                    behavior: "smooth"
                });
                return;
            }

            // Scroll to selected section
            const section = document.querySelector(target);

            if (section) {
                section.scrollIntoView({
                    behavior: "smooth",
                    block: "start"
                });
            }

        });

    });

});

/* =========================================================
   PHISHGUARD - FRONTEND APPLICATION
========================================================= */

let latestReport = null;


/* =========================================================
   EMAIL ANALYSIS
========================================================= */

async function analyzeEmail() {

    const emailInput =
        document.getElementById("emailText");

    const email =
        emailInput.value.trim();

    const loading =
        document.getElementById("loading");

    const error =
        document.getElementById("error");

    const result =
        document.getElementById("result");

    const button =
        document.getElementById("analyzeBtn");


    error.textContent = "";


    /* Empty input */

    if (!email) {

        error.textContent =
            "Please paste an email before starting the analysis.";

        emailInput.focus();

        return;

    }


    /* Loading state */

    loading.style.display = "flex";

    button.disabled = true;

    result.style.display = "none";


    try {

        const response =
            await fetch(
                "/analyze",
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                        email: email
                    })
                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Email analysis failed."
            );

        }


        latestReport = data;

        displayResults(data);


    } catch (err) {

        error.textContent =
            err.message ||
            "Unable to analyze the email.";

    } finally {

        loading.style.display = "none";

        button.disabled = false;

    }

}


/* =========================================================
   DISPLAY RESULTS
========================================================= */

function displayResults(data) {

    const result =
        document.getElementById("result");

    const scorePanel =
        document.getElementById("scorePanel");

    const gauge =
        document.getElementById("gauge");


    result.style.display = "block";


    /* =====================================================
       FINAL RESULT
    ====================================================== */

    const finalResult =
        document.getElementById("finalResult");


    if (data.result === "PHISHING") {

        finalResult.textContent =
            "⚠️ PHISHING";

        finalResult.style.color =
            "#ff6675";

        scorePanel.style.borderColor =
            "rgba(255, 86, 102, .45)";

    } else {

        finalResult.textContent =
            "✅ SAFE";

        finalResult.style.color =
            "#46dc94";

        scorePanel.style.borderColor =
            "rgba(57, 217, 138, .35)";

    }


    document.getElementById("finalScore").textContent =
        data.score + "%";


    document.getElementById("gaugeScore").textContent =
        data.score + "%";


    document.getElementById("riskLevel").textContent =
        data.risk_level;


    /* =====================================================
       RISK GAUGE
    ====================================================== */

    const degrees =
        Math.max(
            0,
            Math.min(
                Number(data.score),
                100
            )
        ) * 3.6;


    let gaugeColor =
        "#39d98a";


    if (data.score >= 50) {
        gaugeColor = "#ff5666";
    }


    if (
        data.score >= 40 &&
        data.score < 50
    ) {
        gaugeColor = "#f3bd4d";
    }


    gauge.style.background =
        `conic-gradient(
            ${gaugeColor} 0deg,
            ${gaugeColor} ${degrees}deg,
            #1d2b3e ${degrees}deg,
            #1d2b3e 360deg
        )`;


    /* =====================================================
       ML ANALYSIS
    ====================================================== */

    document.getElementById("mlPhishing").textContent =
        data.ml.phishing_probability + "%";


    document.getElementById("mlSafe").textContent =
        data.ml.safe_probability + "%";


    document.getElementById("mlBar").style.width =
        Math.min(
            data.ml.phishing_probability,
            100
        ) + "%";


    document.getElementById("safeBar").style.width =
        Math.min(
            data.ml.safe_probability,
            100
        ) + "%";


    /* =====================================================
       URL ANALYSIS
    ====================================================== */

    document.getElementById("urlCount").textContent =
        data.url.total_urls;


    document.getElementById("ipUrls").textContent =
        data.url.ip_urls;


    document.getElementById("httpUrls").textContent =
        data.url.http_urls;


    document.getElementById("httpsUrls").textContent =
        data.url.https_urls;


    document.getElementById("urlRisk").textContent =
        data.url.risk + "%";


    document.getElementById("urlBar").style.width =
        Math.min(
            data.url.risk,
            100
        ) + "%";


    document.getElementById("urlCountLabel").textContent =
        data.url.total_urls + " FOUND";


    /* =====================================================
       THREAT ANALYSIS
    ====================================================== */

    document.getElementById("urgency").textContent =
        data.threat.urgency;


    document.getElementById("credentials").textContent =
        data.threat.credentials;


    document.getElementById("financial").textContent =
        data.threat.financial;


    document.getElementById("threats").textContent =
        data.threat.threats;


    document.getElementById("threatScore").textContent =
        data.threat.score + "%";


    document.getElementById("threatBar").style.width =
        Math.min(
            data.threat.score,
            100
        ) + "%";


    /* =====================================================
       SCAN STATISTICS
    ====================================================== */

    document.getElementById("scanTime").textContent =
        data.scan.timestamp;


    document.getElementById("scanTimeShort").textContent =
        formatShortTimestamp(
            data.scan.timestamp
        );


    document.getElementById("wordCount").textContent =
        data.scan.word_count;


    document.getElementById("characterCount").textContent =
        data.scan.character_count;


    document.getElementById("indicatorCount").textContent =
        data.scan.indicator_count +
        " DETECTED";


    document.getElementById("indicatorCountShort").textContent =
        data.scan.indicator_count;


    document.getElementById("indicatorCountBottom").textContent =
        data.scan.indicator_count;


    /* =====================================================
       RISK INDICATORS
    ====================================================== */

    const indicatorList =
        document.getElementById("indicatorList");


    indicatorList.innerHTML = "";


    if (
        !data.indicators ||
        data.indicators.length === 0
    ) {

        indicatorList.innerHTML =
            `
            <div class="no-indicator">
                ✅ No major phishing indicators detected.
            </div>
            `;

    } else {

        data.indicators.forEach(
            function (indicator) {

                const element =
                    document.createElement("div");


                element.className =
                    "indicator";


                element.textContent =
                    "⚠ " + indicator;


                indicatorList.appendChild(
                    element
                );

            }
        );

    }


    /* =====================================================
       DETECTED URLS
    ====================================================== */

    const urlList =
        document.getElementById("urlList");


    urlList.innerHTML = "";


    if (
        !data.url.urls ||
        data.url.urls.length === 0
    ) {

        urlList.innerHTML =
            `
            <div class="no-indicator">
                ✅ No URLs detected.
            </div>
            `;

    } else {

        data.url.urls.forEach(
            function (url) {

                const element =
                    document.createElement("div");


                element.className =
                    "url-item";


                element.textContent =
                    "🔗 " + url;


                urlList.appendChild(
                    element
                );

            }
        );

    }


    /* =====================================================
       RECOMMENDATION
    ====================================================== */

    const recommendation =
        document.getElementById(
            "recommendationText"
        );


    if (data.result === "PHISHING") {

        recommendation.textContent =
            "HIGH-RISK MESSAGE: Do not click links, " +
            "open suspicious attachments, or provide " +
            "passwords and sensitive information. " +
            "Verify the sender through an independent " +
            "channel and report the message if necessary.";

    } else if (
        data.risk_level === "MEDIUM"
    ) {

        recommendation.textContent =
            "Exercise caution with this message. " +
            "Verify the sender before interacting " +
            "with links or attachments.";

    } else {

        recommendation.textContent =
            "No strong phishing indicators were detected. " +
            "Continue following normal email security practices.";

    }


    /* =====================================================
       SCROLL TO RESULTS
    ====================================================== */

    result.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

}


/* =========================================================
   CLEAR SCANNER
========================================================= */

function clearScanner() {

    document.getElementById(
        "emailText"
    ).value = "";


    document.getElementById(
        "error"
    ).textContent = "";


    document.getElementById(
        "result"
    ).style.display = "none";


    latestReport = null;


    document.getElementById(
        "emailText"
    ).focus();

}


/* =========================================================
   DOWNLOAD REPORT
========================================================= */

async function downloadReport() {

    if (!latestReport) {

        alert(
            "Please analyze an email before downloading the report."
        );

        return;

    }


    try {

        const response =
            await fetch(
                "/download-report",
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body:
                        JSON.stringify(
                            latestReport
                        )
                }
            );


        if (!response.ok) {

            let message =
                "Unable to generate security report.";

            try {

                const errorData =
                    await response.json();

                if (errorData.error) {
                    message =
                        errorData.error;
                }

            } catch (_) {
                /* Ignore invalid error JSON */
            }

            throw new Error(message);

        }


        const blob =
            await response.blob();


        const downloadUrl =
            window.URL.createObjectURL(
                blob
            );


        const link =
            document.createElement("a");


        link.href =
            downloadUrl;


        link.download =
            "phishing_security_report.txt";


        document.body.appendChild(
            link
        );


        link.click();


        link.remove();


        window.URL.revokeObjectURL(
            downloadUrl
        );


    } catch (error) {

        alert(
            error.message
        );

    }

}


/* =========================================================
   FORMAT TIMESTAMP
========================================================= */

function formatShortTimestamp(timestamp) {

    if (!timestamp) {
        return "---";
    }


    /*
       Example:
       05-09-2026 19:45:30
       becomes:
       05-09 19:45
    */

    const parts =
        timestamp.split(" ");


    if (parts.length < 2) {
        return timestamp;
    }


    const datePart =
        parts[0];

    const timePart =
        parts[1];


    return (
        datePart.substring(0, 5) +
        " " +
        timePart.substring(0, 5)
    );

}


/* =========================================================
   KEYBOARD SHORTCUT
========================================================= */

document.addEventListener(
    "keydown",
    function (event) {

        /*
           Ctrl + Enter
           = Analyze email
        */

        if (
            event.ctrlKey &&
            event.key === "Enter"
        ) {

            event.preventDefault();

            analyzeEmail();

        }

    }
);