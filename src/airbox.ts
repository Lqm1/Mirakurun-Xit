/*
   Copyright 2026 Lami

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
import { randomBytes } from "crypto";
import * as apid from "../api";
import XitAirBox, { ATD1Decoder, LiveSession } from "./Mirakurun/XitAirBox";

const KEEPALIVE_INTERVAL = 1000 * 20;

process.title = "Mirakurun: AirBox";

process.stdin.resume();
process.stdin.on("data", () => exit());
process.on("SIGTERM", () => exit());

const opt = {
    host: process.argv[2],
    type: process.argv[3] as apid.ChannelType,
    channel: process.argv[4],
    serviceId: process.argv[5] ? parseInt(process.argv[5], 10) : undefined
};

console.error("airbox:", opt);

const airBox = new XitAirBox(opt.host);
const owner = `mirakurun-${randomBytes(16).toString("hex")}`;

let locked = false;
let exiting = false;
let stream: ATD1Decoder;
let timer: NodeJS.Timeout;

(async () => {
    const pairingKey = await airBox.pair();

    if (await airBox.lock(owner) === false) {
        throw new Error("tuner is locked by another client");
    }
    locked = true;

    stream = await airBox.getLiveStream(opt.type, opt.channel, opt.serviceId, pairingKey);
    stream.once("session", (session: LiveSession) => {
        const keepAlive = async () => {
            try {
                await airBox.exchangeInfo(pairingKey, session);
                if (await airBox.lock(owner) === false) {
                    throw new Error("tuner lock has been lost");
                }
            } catch (err) {
                console.error("airbox:", "(error)", err.message);
                exit(1);
            }
        };
        keepAlive();
        timer = setInterval(keepAlive, KEEPALIVE_INTERVAL);
    });
    stream.once("error", err => {
        console.error("airbox:", "(error)", err.message);
        exit(1);
    });
    stream.once("end", () => exit());
    stream.pipe(process.stdout);
})().catch(err => {
    console.error("airbox:", "(error)", err.message);
    exit(1);
});

async function exit(code = 0) {
    if (exiting) {
        return;
    }
    exiting = true;

    clearInterval(timer);

    if (stream) {
        stream.unpipe();
        stream.destroy();
    }

    if (locked) {
        try {
            await airBox.unlock(owner);
        } catch (err) {
            console.error("airbox:", "(error)", err.message);
        }
    }

    console.error("airbox:", "exit.");

    process.exit(code);
}
