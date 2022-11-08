require("../../../opendsu-sdk/psknode/bundles/openDSU");
openDSURequire('overwrite-require');
const opendsu = openDSURequire("opendsu");
const http = opendsu.loadApi("http");

const ETH_ADAPTER_BASE_URL = "http://localhost:3000";
const DOMAIN = 'ADomainThatDoesntExistMeantJustForTestingCheckEthAdapterTests';

async function createSeedSSI() {
    const keySSISpace = opendsu.loadApi("keyssi");
    const seedSSI = await $$.promisify(keySSISpace.createSeedSSI)(DOMAIN, 'v0');
    return seedSSI;
}

async function getAnchorId(seedSSI, raw = false) {
    const keySSISpace = opendsu.loadApi("keyssi");
    const anchorSSI = keySSISpace.parse(seedSSI.getAnchorId());
    const anchorID = anchorSSI.getIdentifier(raw);
    return anchorID;
}

async function createNewVersionForAnchor(seedSSI, brickMapHash = "hash1", previousVersion) {
    const crypto = opendsu.loadAPI("crypto");
    const keySSISpace = opendsu.loadAPI("keyssi");
    let timestamp = Date.now() + '';
    let anchorID = await getAnchorId(seedSSI, true);
    let dataToSign = anchorID + brickMapHash + timestamp;
    if (previousVersion) {
        previousVersion = keySSISpace.parse(previousVersion);
        previousVersion = previousVersion.getIdentifier(true);
        dataToSign = anchorID + brickMapHash + previousVersion + timestamp;
    }
    let signature = await $$.promisify(crypto.sign)(seedSSI, dataToSign);
    let signedHashLinkSSI1 = keySSISpace.createSignedHashLinkSSI(DOMAIN, brickMapHash, timestamp, signature.toString("base64"));
    return signedHashLinkSSI1.getIdentifier();
}

async function getTotalNumberOfAnchorsTest() {
    try {
        const anchors = await http.fetch(`${ETH_ADAPTER_BASE_URL}/totalNumberOfAnchors`).then(res => res.text());
        console.log(anchors);
        return anchors;
    } catch (e) {
        console.trace(e);
        process.exit(1);
    }
}

async function createAnchorTest(anchorID, anchorVersion) {
    try {
        let doPut = $$.promisify(http.doPut);
        await doPut(`${ETH_ADAPTER_BASE_URL}/createAnchor/${anchorID}/${anchorVersion}`, {});
        console.log(`Created anchor with id ${anchorID} and version ${anchorVersion}`);
    } catch (e) {
        console.trace(e);
        // process.exit(1);
    }
}

// i think DumpAll anchors needs to be a GET with query params. At this moment is a get with a body!!!
//dumpAllAnchorsTest();

const createAnchors = async () => {
    let numberOfCurrentAnchors = await getTotalNumberOfAnchorsTest();
    const NO_ANCHORS = 500;
    const TaskCounter = require("swarmutils").TaskCounter;
    const taskCounter = new TaskCounter(async () => {
        console.timeEnd("anchorProcessing");
        const totalNOAnchors = await getTotalNumberOfAnchorsTest();
        if (NO_ANCHORS !== totalNOAnchors - numberOfCurrentAnchors) {
            throw Error("Some anchors were not created");
        }
    })
    taskCounter.increment(NO_ANCHORS);
    console.time("anchorProcessing")
    for (let i = 0; i < NO_ANCHORS; i++) {
        let dsuIdentifier = await createSeedSSI();
        let anchorId = await getAnchorId(dsuIdentifier);
        let anchorVersion = await createNewVersionForAnchor(dsuIdentifier);
        createAnchorTest(anchorId, anchorVersion).then(response => {
            taskCounter.decrement();
        }).catch(err => {
            console.log(err);
        })
    }
};

createAnchors()