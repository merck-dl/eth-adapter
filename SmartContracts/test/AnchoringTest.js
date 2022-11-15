const assert = require('assert');
const ganache = require('ganache-cli');
const Web3 = require('web3');
const options = {gasLimit: 8000000000};
const web3 = new Web3(ganache.provider(options));

//opendsu
require("../../../opendsu-sdk/psknode/bundles/openDSU");
openDSURequire('overwrite-require');
const opendsuutils = require("../../EthAdapter/utils/opendsuutils");
const opendsu = openDSURequire("opendsu");
//end open dsu
const fs = require('fs');
const solc = require('solc');
const eth = require("../../EthAdapter/utils/eth");
// const Buffer = require("buffer");

let contractConnection;
let contract;
let contractResult;
let accounts;
let estimatedGas = 300000000;

function printErrors(compileRes, showWarnings = false) {
    if (!compileRes) {
        return;
    }
    compileRes.forEach(res => {
        if (res.type !== 'Warning' || showWarnings) {
            console.log(res);
        }
    });
}

beforeEach(async () => {

    try {
        const source = fs.readFileSync('./contracts/Anchoring.sol', 'utf8');
        var input = {
            language: 'Solidity',
            sources: {
                'Anchoring.sol': {
                    content: source
                }
            },
            settings: {
                outputSelection: {
                    '*': {
                        '*': ['*']
                    }
                }
            }
        };


        const compileRes = JSON.parse(solc.compile(JSON.stringify(input)));
        printErrors(compileRes.errors);
        const contrbase = compileRes.contracts['Anchoring.sol']['Anchoring'];
        const abiInterface = contrbase.abi;
        const bytecode = contrbase.evm.bytecode.object;
        accounts = await web3.eth.getAccounts();
        console.log("About to deploy contract");
        try {
            contractConnection = await new web3.eth.Contract(abiInterface);
            contract = contractConnection.deploy({data: bytecode});
            // estimatedGas = await contract.estimateGas();
            // estimatedGas =Math.floor(100000+estimatedGas);
            contractResult = await contract.send({from: accounts[0], gas: estimatedGas}, function (err, res) {
            })
        } catch (e) {
            console.log("Error at deploy", e);
        }
    } catch (err) {
        console.log(err);
    }

});

describe('AnchoringTest', () => {

    it('getVersionsForNonExistentAnchor', async () => {

        const DOMAIN = 'default';
        const keySSISpace = opendsu.loadApi("keyssi");
        const seedSSI = await $$.promisify(keySSISpace.createSeedSSI)(DOMAIN, 'v0', 'hint');
        // const publicKeyRaw = seedSSI.getPublicKey("raw");
        const anchorSSI = keySSISpace.parse(seedSSI.getAnchorId());
        const anchorID = anchorSSI.getIdentifier(true);

        try {
            const anchors = await contractResult.methods.getAllVersions(anchorID).call();
            console.log(anchors)
            assert.equal(anchors.length, 0);
        } catch (e) {
            console.log("Error at encoding", e)
        }
    }).timeout(10000);

    it('createAnchorAndGetVersion', async () => {

        const DOMAIN = 'default';
        const keySSISpace = opendsu.loadApi("keyssi");
        const seedSSI = await $$.promisify(keySSISpace.createSeedSSI)(DOMAIN, 'v0', 'hint');
        // const publicKeyRaw = seedSSI.getPublicKey("raw");
        const anchorSSI = keySSISpace.parse(seedSSI.getAnchorId());
        const anchorID = anchorSSI.getIdentifier(true);
        const crypto = opendsu.loadAPI("crypto");
        const publicKey = anchorSSI.getControlString();
        const timestamp = Date.now() + '';
        const brickMapHash = "hash";
        const dataToSign = anchorID + brickMapHash + timestamp;
        const signature = await $$.promisify(crypto.sign)(seedSSI, dataToSign);
        const signatureHex = "0x" + signature.toString("hex");
        const newSignedHashLinkSSI = keySSISpace.createSignedHashLinkSSI(DOMAIN, brickMapHash, timestamp, signature.toString("base64"));
        const signedHLSSI = newSignedHashLinkSSI.getIdentifier(true);
        console.log("dataToSign", dataToSign);
        console.log("publicKey hex", Buffer.from(publicKey, "base64").toString("hex"));
        console.log("signature", signatureHex);
        console.log(anchorSSI.getIdentifier())
        console.log(newSignedHashLinkSSI.getIdentifier())
        let v = eth.getV(signatureHex, Buffer.from(publicKey, "base64").toString("hex"), dataToSign);
        console.log("anchorID", anchorID);
        console.log("newAnchorValue", signedHLSSI);
        console.log("v");
        console.log("hash", crypto.sha256JOSE(dataToSign).toString("hex"))
        let result;
        try {
            let command = await contractResult.methods.createAnchor(anchorID, signedHLSSI);
            try {
                result = await command.send({
                    from: accounts[0],
                    gas: estimatedGas
                });

                console.log(result.events.UIntResult);
                assert.equal(result.events.InvokeStatus.returnValues.statusCode, 200);
            } catch (e) {
                console.log("Error at sending data to smart contract", e)
            }

            const anchors = await contractResult.methods.getAllVersions(anchorID).call();
            console.log(anchors)
            assert.equal(anchors.length, 1);
            // assert.equal(anchors[0], signedHLSSI);
        } catch (e) {
            console.log("Error at encoding", e)
        }
    }).timeout(100000);

    it('createConstAnchorAndGetVersion', async () => {

        const DOMAIN = 'default';
        const keySSISpace = opendsu.loadApi("keyssi");
        const seedSSI = keySSISpace.createConstSSI(DOMAIN, 'content', 'v0', 'hint');
        // const publicKeyRaw = seedSSI.getPublicKey("raw");
        const anchorSSI = keySSISpace.parse(seedSSI.getAnchorId());
        const anchorID = anchorSSI.getIdentifier(true);
        const brickMapHash = "hash";
        const hashLinkSSI = keySSISpace.createHashLinkSSI(DOMAIN, brickMapHash);
        const signedHLSSI = hashLinkSSI.getIdentifier(true);
        const v = 0;
        let result;
        try {
            let command = await contractResult.methods.createAnchor(anchorID, signedHLSSI);
            try {
                result = await command.send({
                    from: accounts[0],
                    gas: estimatedGas
                });

                // console.log(result.events.BoolResult.returnValues.str)
                assert.equal(result.events.InvokeStatus.returnValues.statusCode, 200);
            } catch (e) {
                console.log("Error at sending data to smart contract", e)
            }

            const anchors = await contractResult.methods.getAllVersions(anchorID).call();
            console.log(anchors)
            assert.equal(anchors.length, 1);
            assert.equal(anchors[0], signedHLSSI);
        } catch (e) {
            console.log("Error at encoding", e)
        }
    }).timeout(100000);

    it('tryingToAppendToConstAnchorAndGetVersion', async () => {

        const DOMAIN = 'default';
        const keySSISpace = opendsu.loadApi("keyssi");
        const seedSSI = keySSISpace.createConstSSI(DOMAIN, 'content', 'v0', 'hint');
        // const publicKeyRaw = seedSSI.getPublicKey("raw");
        const anchorSSI = keySSISpace.parse(seedSSI.getAnchorId());
        const anchorID = anchorSSI.getIdentifier(true);
        let brickMapHash = "hash";
        let hashLinkSSI = keySSISpace.createHashLinkSSI(DOMAIN, brickMapHash);
        let signedHLSSI = hashLinkSSI.getIdentifier(true);
        const v = 0;
        let result;
        try {
            let command = await contractResult.methods.createAnchor(anchorID, signedHLSSI);
            try {
                result = await command.send({
                    from: accounts[0],
                    gas: estimatedGas
                });

                assert.equal(result.events.InvokeStatus.returnValues.statusCode, 200);


            } catch (e) {
                console.log("Error at sending data to smart contract", e)
            }

            brickMapHash = "hash";
            hashLinkSSI = keySSISpace.createHashLinkSSI(DOMAIN, brickMapHash);
            signedHLSSI = hashLinkSSI.getIdentifier(true);
            command = await contractResult.methods.appendAnchor(anchorID, signedHLSSI);
            try {
                result = await command.send({
                    from: accounts[0],
                    gas: estimatedGas
                });

                // console.log(result.events.BoolResult.returnValues.str)
                assert.equal(result.events.InvokeStatus.returnValues.statusCode, 107);


            } catch (e) {
                console.log("Error at sending data to smart contract", e)
            }
        } catch (e) {
            console.log("Error at encoding", e)
        }
    }).timeout(100000);

    it('appendAnchorAndGetVersions', async () => {

        const DOMAIN = 'default';
        const keySSISpace = opendsu.loadApi("keyssi");
        const seedSSI = await $$.promisify(keySSISpace.createSeedSSI)(DOMAIN, 'v0', 'hint');
        // const publicKeyRaw = seedSSI.getPublicKey("raw");
        const anchorSSI = keySSISpace.parse(seedSSI.getAnchorId());
        const anchorID = anchorSSI.getIdentifier(true);
        const crypto = opendsu.loadAPI("crypto");
        const publicKey = anchorSSI.getControlString();
        let timestamp = Date.now() + '';
        let brickMapHash = "hash1";
        let dataToSign = anchorID + brickMapHash + timestamp;
        let signature = await $$.promisify(crypto.sign)(seedSSI, dataToSign);
        let signatureHex = "0x" + signature.toString("hex");
        let signedHashLinkSSI1 = keySSISpace.createSignedHashLinkSSI(DOMAIN, brickMapHash, timestamp, signature.toString("base64"));
        let signedHLSSI1 = signedHashLinkSSI1.getIdentifier(true);
        let v = eth.getV(signatureHex, Buffer.from(publicKey, "base64").toString("hex"), dataToSign);
        console.log(anchorSSI.getIdentifier());
        console.log(signedHashLinkSSI1.getIdentifier());
        let result;
        try {
            let command = await contractResult.methods.createAnchor(anchorID, signedHLSSI1);
            try {
                result = await command.send({
                    from: accounts[0],
                    gas: estimatedGas
                });

                brickMapHash = "hash2"
                timestamp = Date.now();
                dataToSign = anchorID + brickMapHash + signedHLSSI1 + timestamp;
                signature = await $$.promisify(crypto.sign)(seedSSI, dataToSign);
                signatureHex = "0x" + signature.toString("hex");
                console.log("data to sign", dataToSign);
                console.log("signature", signatureHex)
                signedHashLinkSSI1 = keySSISpace.createSignedHashLinkSSI(DOMAIN, brickMapHash, timestamp, signature.toString("base64"));
                signedHLSSI1 = signedHashLinkSSI1.getIdentifier(true);
                console.log(signedHashLinkSSI1.getIdentifier());
                v = eth.getV(signatureHex, Buffer.from(publicKey, "base64").toString("hex"), dataToSign);

                assert.equal(result.events.InvokeStatus.returnValues.statusCode, 200);
                command = await contractResult.methods.appendAnchor(anchorID, signedHLSSI1);
                result = await command.send({
                    from: accounts[0],
                    gas: estimatedGas
                });

                console.log(result.events.InvokeStatus.returnValues.statusCode);
                assert.equal(result.events.InvokeStatus.returnValues.statusCode, 200);
            } catch (e) {
                console.log("Error at sending data to smart contract", e)
            }


            const anchors = await contractResult.methods.getAllVersions(anchorID).call();
            console.log(anchors)
            assert.equal(anchors.length, 2);
            assert.equal(anchors[1], signedHLSSI1);

            const totalNoAnchors = await contractResult.methods.totalNumberOfAnchors().call();
            console.log(totalNoAnchors);
            assert.equal(totalNoAnchors, 1);

            const listAnchors = await contractResult.methods.dumpAnchors(0, 1, 1000).call();
            console.log(listAnchors);
            assert.equal(listAnchors.length, 1);
            assert.equal(listAnchors[0].anchorId, anchorID);
            assert.equal(listAnchors[0].anchorValues[1], signedHLSSI1);
        } catch (e) {
            console.log("Error at encoding", e)
        }
    }).timeout(100000);

    it('createOrAppendMultipleAnchors', async () => {

        const DOMAIN = 'default';
        const keySSISpace = opendsu.loadApi("keyssi");
        let NO_ANCHORS = 50;
        let anchors = '';
        let anchorsArray = []
        let anchorsObjArr = [];
        for (let i = 0; i < NO_ANCHORS; i++) {
            const seedSSI = await $$.promisify(keySSISpace.createSeedSSI)(DOMAIN, 'v0', 'hint');
            // const publicKeyRaw = seedSSI.getPublicKey("raw");
            const anchorSSI = keySSISpace.parse(seedSSI.getAnchorId());
            const anchorID = anchorSSI.getIdentifier(true);
            const crypto = opendsu.loadAPI("crypto");
            const publicKey = anchorSSI.getControlString();
            const timestamp = Date.now() + '';
            let brickMapHash = "hash1";
            let dataToSign = anchorID + brickMapHash + timestamp;
            let signature = await $$.promisify(crypto.sign)(seedSSI, dataToSign);
            let signatureHex = "0x" + signature.toString("hex");
            let signedHashLinkSSI1 = keySSISpace.createSignedHashLinkSSI(DOMAIN, brickMapHash, timestamp, signature.toString("base64"));
            let signedHLSSI1 = signedHashLinkSSI1.getIdentifier(true);
            let v = eth.getV(signatureHex, Buffer.from(publicKey, "base64").toString("hex"), dataToSign);
            anchorsArray.push(anchorID);
            anchorsArray.push(signedHLSSI1);
            anchorsObjArr.push({
                anchorId: anchorID,
                anchorValue: signedHLSSI1
            })
        }

        console.log(anchorsObjArr);
        let result;
        try {
            let command = await contractResult.methods.createOrUpdateMultipleAnchors(anchorsArray);
            try {
                result = await command.send({
                    from: accounts[0],
                    gas: estimatedGas
                });


                // console.log(result.events.StringResult.returnValues.str);
                assert.equal(result.events.InvokeStatus.returnValues.statusCode, 200);
                // assert.equal(result.events.InvokeStatus.returnValues.statusCode, 200);
            } catch (e) {
                console.log("Error at sending data to smart contract", e)
            }


            // const anchors = await contractResult.methods.getAllVersions(anchorID).call();
            // console.log(anchors)
            // assert.equal(anchors.length, 2);
            // assert.equal(anchors[1], signedHLSSI1);
        } catch (e) {
            console.log("Error at encoding", e)
        }
    }).timeout(100000);
});
