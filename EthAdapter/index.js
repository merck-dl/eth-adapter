function requestBodyJSONMiddleware(request, response, next) {
    response.setHeader('Content-Type', 'application/json');

    const data = [];

    request.on('data', (chunk) => {
        data.push(chunk);
    });

    request.on('end', () => {
        let jsonBody = {};
        try {
            jsonBody = data.length ? JSON.parse(data) : {};
        } catch (err) {
            console.log(err);
        }
        request.body = jsonBody;
        next();
    });
}

function boot() {
    const port = 3000;
    const express = require('express');

    let app = express();
    const TokenBucket = require("./services/TokenBucket");
    const tokenBucket = new TokenBucket(200, 200, 10000);

    app.use(function (req, res, next) {
        res.setHeader('Access-Control-Allow-Origin', '*');
        // Request methods allowed
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
        // Request headers allowed
        res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Content-Length, X-Content-Length');
        next();
    });

    //the following line is not really necessary but prevents a bug related to the fact we need to require web3 before opendsu bundle
    require("./services/transactionManager").getInstance();

    //this require needs to be called after the web3 library require to don't interfere
    require("../../opendsu-sdk/psknode/bundles/openDSU");
    openDSURequire('overwrite-require');

    app.use(requestBodyJSONMiddleware);

    function throttlerMiddleware(req, res, next) {
        tokenBucket.takeToken("*", 1, (err) => {
            if (err) {
                if (err === TokenBucket.ERROR_LIMIT_EXCEEDED) {
                    res.statusCode = 429;
                } else {
                    res.statusCode = 500;
                }

                res.end();
                return;
            }
            next();
        });
    }

    app.use(throttlerMiddleware);

    const createAnchorHandler = require("./controllers/createAnchor");
    app.put("/createAnchor/:anchorId/:anchorValue", createAnchorHandler);

    const appendAnchorHandler = require("./controllers/appendAnchor");
    app.put("/appendAnchor/:anchorId/:anchorValue", appendAnchorHandler);

    const createOrUpdateMultipleAnchorsHandler = require("./controllers/createOrUpdateMultipleAnchors");
    app.put("/createOrAppendMultipleAnchors", createOrUpdateMultipleAnchorsHandler);

    const getAllVersionsHandler = require("./controllers/getAllVersions");
    app.get("/getAllVersions/:anchorId", getAllVersionsHandler);

    const getLastVersionHandler = require("./controllers/getLastVersion");
    app.get("/getLastVersion/:anchorId", getLastVersionHandler);

    const totalNumberOfAnchors = require("./controllers/totalNumberOfAnchors");
    app.get("/totalNumberOfAnchors", totalNumberOfAnchors);

    const dumpAnchors = require("./controllers/dumpAnchors");
    app.get("/dumpAnchors", dumpAnchors);

    app.get("/health", function (req, res, next) {
        res.status(200).send();
    });

    let server = app.listen(port);

    process.on('SIGTERM', () => {
        console.log('SIGTERM signal received: closing ETH Adapter');
        server.close(() => {
            console.log('ETH Adapter stopped!');
        });
    });

    console.log('EthAdapter is ready. Listening on port', port);
}

boot();