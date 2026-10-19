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
import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual, Decipher } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import * as http from "http";
import { dirname } from "path";
import { Transform, TransformCallback } from "stream";
import { TsChar, TsCrc32 } from "@chinachu/aribts";
import { XMLParser } from "fast-xml-parser";
import * as apid from "../../api";
import { COMPONENT_TYPE, SAMPLING_RATE, getLangCode } from "./EPG";
import { getProgramItemId } from "./Program";
import ServiceItem from "./ServiceItem";

const CONTROL_PORT = 49152;
const REQUEST_TIMEOUT = 5000;
const STREAM_TIMEOUT = 10000;

/** client common authentication key (Ka) */
const AUTH_KEY = Buffer.from("196f50af1c26471a9eb8bc4ee677c040", "hex");
/** client device key (Kd) */
const DEVICE_KEY = Buffer.from("40f92968880576af7b39f82d3839f4c6", "hex");
/** client information (Iclient) */
const CLIENT_INFO = Buffer.concat([
    Buffer.from("0100000000000001", "hex"),
    invertString("Mirakurun-Xit"),
    invertString("Linux"),
    Buffer.alloc(24)
]);

const OBJECT_IDS: { [type in apid.ChannelType]?: string } = {
    GR: "10",
    BS: "11",
    CS: "12"
};

const PACKET_SIZE = 188;
const ATD1_HEADER_SIZE = 188;

// the transcoded stream has the video and audio on fixed PIDs but PMT doesn't
const VIDEO_PID = 0x0002;
const AUDIO_PID = 0x0003;
const VIDEO_STREAM_TYPES = [0x01, 0x02, 0x1B, 0x24];
const AUDIO_STREAM_TYPES = [0x03, 0x04, 0x0F, 0x11];

const xmlParser = new XMLParser({
    removeNSPrefix: true,
    ignoreAttributes: false,
    parseTagValue: false,
    isArray: name => name === "item" || name === "res"
});

interface Pairing {
    host: string;
    /** R[16] || AES-128-ECB(MD5(R || Kd), Kp) */
    key: string;
}

interface Item {
    networkId: number;
    transportStreamId: number;
    serviceId: number;
    name: string;
    type: number;
    frequency: number;
    remoteControlKeyId: number;
    url: string;
}

export interface LiveSession {
    serverNonce: Buffer;
    sequence: number;
}

export default class XitAirBox {
    constructor(readonly host: string) {}

    async getServices(type: apid.ChannelType, channel: string): Promise<apid.Service[]> {
        const items = (await this._browse(type)).filter(item => getChannel(type, item) === channel);

        // only the primary service has the key, but Mirakurun gives the key of TS to all services
        const remoteControlKeyId = Math.max(-1, ...items.map(item => item.remoteControlKeyId));

        return items.map(item => ({
            id: ServiceItem.getId(item.networkId, item.serviceId),
            networkId: item.networkId,
            serviceId: item.serviceId,
            name: item.name,
            type: item.type,
            logoId: -1,
            remoteControlKeyId
        }));
    }

    async getPrograms(networkId: number): Promise<apid.Program[]> {
        const wave = networkId === 4 ? "bs" : (networkId === 6 || networkId === 7) ? "cs" : "tb";
        const res = await request({
            host: this.host,
            port: CONTROL_PORT,
            path: `/epg/${wave}/0x${networkId.toString(16).padStart(4, "0")}`
        });
        if (res.statusCode !== 200) {
            throw new Error(`failed to get EPG (${res.statusCode})`);
        }

        return decodeEPG(res.body, networkId);
    }

    async getLiveStream(type: apid.ChannelType, channel: string, serviceId: number, pairingKey: Buffer): Promise<ATD1Decoder> {
        const item = (await this._browse(type)).find(item => {
            return getChannel(type, item) === channel && (!serviceId || item.serviceId === serviceId);
        });
        if (!item) {
            throw new Error(`service not found (type=${type}, channel=${channel}, serviceId=${serviceId})`);
        }

        const url = new URL(item.url);
        // the path is used for the key derivation so it must be sent as is
        const path = item.url.slice(url.origin.length);
        const uid = randomBytes(16);

        const res = await new Promise<http.IncomingMessage>((resolve, reject) => {
            const req = http.get({
                host: url.hostname,
                port: url.port,
                path,
                headers: {
                    "AT-ClientUID": toHex(uid),
                    "AT-ClientID": toHex(encrypt("aes-128-ecb", md5(uid, AUTH_KEY), null, DEVICE_KEY)),
                    "transferMode.dlna.org": "Background"
                },
                timeout: STREAM_TIMEOUT,
                agent: false
            }, resolve);
            req.on("timeout", () => req.destroy(new Error("live stream has timed out")));
            req.on("error", reject);
        });
        if (res.statusCode !== 200) {
            res.destroy();
            throw new Error(`failed to get live stream (${res.statusCode})`);
        }

        const decoder = new ATD1Decoder(path, pairingKey, uid);
        res.pipe(decoder);
        res.once("error", err => decoder.destroy(err));
        decoder.once("close", () => res.destroy());

        return decoder;
    }

    /**
     * returns the pairing key (Kp). pairs with the device if the saved key is not available.
     */
    async pair(): Promise<Buffer> {
        const pairings = loadPairings();
        const pairing = pairings.find(pairing => pairing.host === this.host);

        if (pairing) {
            const pairingKey = decryptPairingKey(Buffer.from(pairing.key, "hex"));
            const { status } = await this._requestPairing(
                "X_AuthenticatePairing",
                Buffer.concat([DEVICE_KEY, CLIENT_INFO, pairingKey])
            );
            if (status === 0) {
                return pairingKey;
            }
        }

        const { status, data } = await this._requestPairing("X_RequestPairing", Buffer.concat([DEVICE_KEY, CLIENT_INFO]));
        if (status !== 0) {
            throw new Error(`pairing has failed (status=${status})`);
        }

        // Ks[16] || Iserver[64] || Kp[16]
        const pairingKey = data.subarray(80, 96);

        savePairings([
            ...pairings.filter(pairing => pairing.host !== this.host),
            { host: this.host, key: encryptPairingKey(pairingKey).toString("hex") }
        ]);

        return pairingKey;
    }

    async lock(owner: string): Promise<boolean> {
        const res = await this._soap("X_AirTunerControl", "X_LockAirTuner", { uniqueID: owner });
        return res.result === "1";
    }

    async unlock(owner: string): Promise<void> {
        await this._soap("X_AirTunerControl", "X_UnlockAirTuner", { uniqueID: owner });
    }

    /**
     * mutual authentication to keep the live session
     */
    async exchangeInfo(pairingKey: Buffer, session: LiveSession): Promise<void> {
        session.sequence = (session.sequence + 1) >>> 0;
        const sequence = Buffer.alloc(4);
        sequence.writeUInt32BE(session.sequence);
        const clientNonce = randomBytes(16);

        const res = await this._soap("X_AirTunerControl", "X_ExchangeInfo", {
            ClientInformation: toHex(Buffer.concat([md5(sequence, session.serverNonce, pairingKey), clientNonce]))
        });

        // tag[16] || next server nonce[16]
        const info = Buffer.from(res.ServerInformation || "", "hex");
        if (info.length !== 32 || timingSafeEqual(info.subarray(0, 16), md5(sequence, clientNonce, pairingKey)) === false) {
            throw new Error("X_ExchangeInfo verification has failed");
        }

        session.serverNonce = info.subarray(16);
    }

    private async _requestPairing(action: string, payload: Buffer): Promise<{ status: number; data: Buffer }> {
        const clientNonce = randomBytes(16);
        const iv = randomBytes(16);
        const req = Buffer.concat([
            clientNonce,
            iv,
            encrypt("aes-128-cbc", md5(clientNonce, AUTH_KEY), iv, Buffer.concat([payload, md5(clientNonce, iv, payload)]))
        ]);

        const { Response } = await this._soap("X_AirTunerControl", action, { Request: toHex(req) });

        // status[1] || reserved[3] || server nonce[16] || iv[16] || encrypted (data || checksum[16])
        const res = Buffer.from(Response || "", "hex");
        const decrypted = decrypt(
            "aes-128-cbc",
            md5(clientNonce, res.subarray(4, 20), AUTH_KEY),
            res.subarray(20, 36),
            res.subarray(36)
        );
        const data = decrypted.subarray(0, -16);
        if (md5(res.subarray(0, 36), data).equals(decrypted.subarray(-16)) === false) {
            throw new Error(`${action} response checksum mismatch`);
        }

        return { status: res[0], data };
    }

    private async _browse(type: apid.ChannelType): Promise<Item[]> {
        const objectId = OBJECT_IDS[type];
        if (!objectId) {
            return [];
        }

        const items: Item[] = [];

        let index = 0;
        while (true) {
            const res = await this._soap("ContentDirectory", "Browse", {
                ObjectID: objectId,
                BrowseFlag: "BrowseDirectChildren",
                Filter: "*",
                StartingIndex: index,
                RequestedCount: 16,
                SortCriteria: ""
            });

            for (const item of xmlParser.parse(res.Result)["DIDL-Lite"].item || []) {
                const live = item.res.find(r => /^http-get:\*:video\/x-atd1:/i.test(r["@_protocolInfo"]));
                if (!live) {
                    continue;
                }

                items.push({
                    networkId: parseInt(item.networkID, 16),
                    transportStreamId: parseInt(item.transportStreamID, 16),
                    serviceId: parseInt(item.serviceID, 16),
                    name: item.channelName,
                    type: parseInt(item.serviceType, 16),
                    frequency: parseInt(item.frequency, 10),
                    // e.g. "040410" -> 4
                    remoteControlKeyId: parseInt(item.channelNr.slice(0, 2), 10) || -1,
                    url: live["#text"]
                });
            }

            const returned = parseInt(res.NumberReturned, 10);
            index += returned;
            if (returned === 0 || index >= parseInt(res.TotalMatches, 10)) {
                break;
            }
        }

        return items;
    }

    private async _soap(
        service: string,
        action: string,
        args: { [name: string]: string | number }
    ): Promise<{ [name: string]: string }> {
        const serviceType = `urn:schemas-${service === "ContentDirectory" ? "upnp-org" : "pixela.jp"}:service:${service}:1`;
        const body = `<?xml version="1.0" encoding="utf-8"?>` +
            `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
            `<s:Body><u:${action} xmlns:u="${serviceType}">` +
            Object.keys(args).map(name => `<${name}>${args[name]}</${name}>`).join("") +
            `</u:${action}></s:Body></s:Envelope>`;

        const res = await request({
            host: this.host,
            port: CONTROL_PORT,
            path: `/upnp/control/${service}`,
            method: "POST",
            headers: {
                "Content-Type": `text/xml; charset="utf-8"`,
                "Content-Length": Buffer.byteLength(body),
                "SOAPAction": `"${serviceType}#${action}"`
            }
        }, body);

        const envelope = xmlParser.parse(res.body.toString("utf8")).Envelope;
        if (res.statusCode !== 200) {
            const error = envelope?.Body?.Fault?.detail?.UPnPError;
            throw new Error(`${action} has failed (${res.statusCode} ${error?.errorDescription || ""})`);
        }

        return envelope.Body[`${action}Response`];
    }
}

/**
 * decrypts ATD1 stream into MPEG-2 TS.
 * emits `session` event when the header has been verified.
 */
export class ATD1Decoder extends Transform {
    private _headerKey: Buffer;
    private _header = Buffer.alloc(0);
    private _decipher: Decipher = null;
    private _remainder = Buffer.alloc(0);
    private _pmtPid = -1;
    private _pmtPackets: Buffer[] = [];

    constructor(path: string, pairingKey: Buffer, private _uid: Buffer) {
        super();
        this._headerKey = md5(Buffer.from(path.slice(1), "ascii"), pairingKey);
    }

    _transform(chunk: Buffer, encoding: BufferEncoding, callback: TransformCallback): void {
        if (this._decipher === null) {
            this._header = Buffer.concat([this._header, chunk]);
            if (this._header.length < ATD1_HEADER_SIZE) {
                callback();
                return;
            }

            // the first 12 bytes are not encrypted
            const encrypted = this._header.subarray(0, ATD1_HEADER_SIZE);
            const header = Buffer.concat([
                encrypted.subarray(0, 12),
                decrypt("aes-128-cbc", this._headerKey, this._uid, encrypted.subarray(12))
            ]);
            if (md5(header.subarray(0, 172)).equals(header.subarray(172)) === false) {
                callback(new Error("ATD1 header checksum mismatch"));
                return;
            }

            const serverNonce = header.subarray(24, 40);
            this._decipher = createDecipheriv("aes-128-cbc", md5(serverNonce, encrypted.subarray(172)), this._uid)
                .setAutoPadding(false);

            const session: LiveSession = { serverNonce, sequence: header.readUInt32BE(40) };
            this.emit("session", session);

            chunk = this._header.subarray(ATD1_HEADER_SIZE);
            this._header = null;
        }

        const data = Buffer.concat([this._remainder, this._decipher.update(chunk)]);
        const length = data.length - data.length % PACKET_SIZE;
        this._remainder = data.subarray(length);

        const packets: Buffer[] = [];
        for (let offset = 0; offset < length; offset += PACKET_SIZE) {
            const packet = data.subarray(offset, offset + PACKET_SIZE);
            const pid = packet.readUInt16BE(1) & 0x1FFF;
            const isStart = (packet[1] & 0x40) !== 0;

            if (pid === 0 && isStart) {
                this._pmtPid = getPMTPid(packet);
            }
            if (pid !== this._pmtPid) {
                packets.push(packet);
                continue;
            }

            // hold PMT packets until the section is completed
            if (isStart) {
                this._pmtPackets = [packet];
            } else if (this._pmtPackets.length !== 0) {
                this._pmtPackets.push(packet);
            }
            if (this._pmtPackets.length !== 0 && normalizePMT(this._pmtPackets)) {
                packets.push(...this._pmtPackets);
                this._pmtPackets = [];
            }
        }

        callback(null, Buffer.concat(packets));
    }
}

export function decodeEPG(data: Buffer, networkId: number): apid.Program[] {
    // each byte is scrambled with the byte 16 bytes before
    const epg = Buffer.allocUnsafe(Math.max(data.length - 16, 0));
    for (let i = 0; i < epg.length; i++) {
        epg[i] = data[i + 16] ^ data[i];
    }
    if (epg.length < 4 || epg.readUInt32BE(0) !== 0xAAAAAAAA) {
        throw new Error("invalid EPG data");
    }

    // network index: 12 bytes each
    let offset = 4;
    while (epg.readUInt32BE(offset) !== 0xBBBBBBBB) {
        offset += 12;
    }
    offset += 4;

    // service index: 12 bytes each
    const networkIds = new Map<number, number>();
    while (epg.readUInt32BE(offset) !== 0xCCCCCCCC) {
        networkIds.set(epg.readUInt16BE(offset + 4), epg.readUInt16BE(offset + 2));
        offset += 12;
    }
    offset += 4;

    const programs: apid.Program[] = [];

    while (offset + 22 <= epg.length) {
        const start = epg.readUInt32BE(offset);
        const duration = epg.readUInt32BE(offset + 4);
        const serviceId = epg.readUInt16BE(offset + 8);
        const eventId = epg.readUInt16BE(offset + 10);
        const counts = epg.subarray(offset + 12, offset + 22);
        offset += 22;

        const program: apid.Program = {
            id: getProgramItemId(networkId, serviceId, eventId),
            eventId,
            serviceId,
            networkId,
            // the time is shifted to JST
            startAt: (start - 32400) * 1000,
            duration: duration * 1000,
            isFree: counts[2] === 0
        };

        const relatedItems: apid.ProgramRelatedItem[] = [];
        for (let i = 0; i < counts[3]; i++, offset += 4) {
            const item: apid.ProgramRelatedItem = {
                type: "shared",
                networkId,
                serviceId: epg.readUInt16BE(offset),
                eventId: epg.readUInt16BE(offset + 2)
            };
            if (item.serviceId !== serviceId || item.eventId !== eventId) {
                relatedItems.push(item);
            }
        }
        if (relatedItems.length !== 0) {
            program.relatedItems = relatedItems;
        }

        // component_type[1] || component_tag[1]
        if (counts[4] !== 0) {
            program.video = {
                // video of ISDB 2K services is MPEG-2
                type: "mpeg2",
                resolution: COMPONENT_TYPE[epg[offset]] || null,
                streamContent: 1,
                componentType: epg[offset]
            };
        }
        offset += counts[4] * 2;

        const audios: apid.ProgramAudio[] = [];
        for (let i = 0; i < counts[5]; i++, offset += 14) {
            const langs = [getLangCode(epg.subarray(offset + 7, offset + 10))];
            if (epg[offset + 2] === 1) {
                langs.push(getLangCode(epg.subarray(offset + 11, offset + 14)));
            }

            audios.push({
                componentType: epg[offset],
                componentTag: epg[offset + 1],
                isMain: epg[offset + 3] === 1,
                samplingRate: SAMPLING_RATE[epg[offset + 5]],
                langs
            });
        }
        if (audios.length !== 0) {
            program.audios = audios;
        }

        offset += counts[6] * 11 + counts[7] * 10;

        if (counts[8] === 1) {
            const nameLength = epg[offset];
            const descriptionLength = epg[offset + 1];
            offset += 2;

            program.name = new TsChar(epg.subarray(offset, offset + nameLength)).decode();
            offset += nameLength;
            program.description = new TsChar(epg.subarray(offset, offset + descriptionLength)).decode();
            offset += descriptionLength;

            // genre[3] || user nibbles[4] || unknown[4]
            program.genres = [];
            for (let i = 0; i < 3; i++) {
                if (epg[offset + i] !== 0xFF) {
                    program.genres.push({
                        lv1: epg[offset + i] >> 4,
                        lv2: epg[offset + i] & 0x0F,
                        un1: epg[offset + 3 + i] >> 4,
                        un2: epg[offset + 3 + i] & 0x0F
                    });
                }
            }
            offset += 11;
        }

        if (
            networkIds.get(serviceId) !== networkId ||
            start === 0xFFFFFFFF ||
            duration === 0 ||
            duration === 0xFFFFFFFF ||
            // placeholder for the service which has no EPG
            (!program.name && !program.relatedItems)
        ) {
            continue;
        }

        programs.push(program);
    }

    return programs;
}

/**
 * returns the channel for Mirakurun from the item of Browse.
 */
function getChannel(type: apid.ChannelType, item: Item): string {
    switch (type) {
        case "GR":
            // UHF 13ch = 473MHz, 6MHz step
            return String(13 + Math.round((item.frequency - 473) / 6));
        case "BS":
            return `BS${String((item.transportStreamId >> 4) & 0x1F).padStart(2, "0")}_${item.transportStreamId & 0x07}`;
        case "CS":
            return `CS${(item.transportStreamId >> 4) & 0x1F}`;
    }
}

function getPayloadOffset(packet: Buffer): number {
    // adaptation_field_control
    return 4 + ((packet[3] & 0x20) !== 0 ? 1 + packet[4] : 0);
}

function getPMTPid(packet: Buffer): number {
    const offset = getPayloadOffset(packet);
    const section = packet.subarray(offset + 1 + packet[offset]);
    const end = Math.min(3 + (section.readUInt16BE(1) & 0x0FFF) - 4, section.length);

    for (let i = 8; i + 4 <= end; i += 4) {
        // program_number 0 is for NIT
        if (section.readUInt16BE(i) !== 0) {
            return section.readUInt16BE(i + 2) & 0x1FFF;
        }
    }

    return -1;
}

/**
 * rewrites PMT in the packets to point the actual video/audio PIDs.
 * returns `false` if the section is not completed.
 */
function normalizePMT(packets: Buffer[]): boolean {
    const offsets = packets.map(packet => getPayloadOffset(packet));
    // pointer_field
    offsets[0] += 1 + packets[0][offsets[0]];

    const section = Buffer.concat(packets.map((packet, i) => packet.subarray(offsets[i])));
    if (section.length < 3 || section.length < 3 + (section.readUInt16BE(1) & 0x0FFF)) {
        return false;
    }

    const end = 3 + (section.readUInt16BE(1) & 0x0FFF) - 4;
    const pcrPid = section.readUInt16BE(8) & 0x1FFF;
    let videoPid = -1;
    let audioPid = -1;

    let i = 12 + (section.readUInt16BE(10) & 0x0FFF);
    while (i + 5 <= end) {
        const pid = section.readUInt16BE(i + 1) & 0x1FFF;

        if (videoPid === -1 && VIDEO_STREAM_TYPES.includes(section[i])) {
            videoPid = pid;
            section[i] = 0x1B;
            section.writeUInt16BE(0xE000 | VIDEO_PID, i + 1);
        } else if (audioPid === -1 && AUDIO_STREAM_TYPES.includes(section[i])) {
            audioPid = pid;
            section[i] = 0x0F;
            section.writeUInt16BE(0xE000 | AUDIO_PID, i + 1);
        }

        i += 5 + (section.readUInt16BE(i + 3) & 0x0FFF);
    }

    if (pcrPid === videoPid) {
        section.writeUInt16BE(0xE000 | VIDEO_PID, 8);
    } else if (pcrPid === audioPid) {
        section.writeUInt16BE(0xE000 | AUDIO_PID, 8);
    }

    section.writeInt32BE(TsCrc32.calc(section.subarray(0, end)), end);

    let copied = 0;
    packets.forEach((packet, i) => {
        copied += section.copy(packet, offsets[i], copied);
    });

    return true;
}

function loadPairings(): Pairing[] {
    const path = process.env.AIRBOX_DB_PATH;
    if (existsSync(path) === false) {
        return [];
    }

    try {
        return JSON.parse(readFileSync(path, "utf8"));
    } catch (e) {
        return [];
    }
}

function savePairings(pairings: Pairing[]): void {
    const path = process.env.AIRBOX_DB_PATH;
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(pairings));
}

function encryptPairingKey(pairingKey: Buffer): Buffer {
    const salt = randomBytes(16);
    return Buffer.concat([salt, encrypt("aes-128-ecb", md5(salt, DEVICE_KEY), null, pairingKey)]);
}

function decryptPairingKey(data: Buffer): Buffer {
    return decrypt("aes-128-ecb", md5(data.subarray(0, 16), DEVICE_KEY), null, data.subarray(16, 32));
}

function request(options: http.RequestOptions, body?: string): Promise<{ statusCode: number; body: Buffer }> {
    return new Promise((resolve, reject) => {
        const req = http.request({
            timeout: REQUEST_TIMEOUT,
            // the device closes kept-alive connections without notice
            agent: false,
            ...options
        }, res => {
            const chunks: Buffer[] = [];
            res.on("data", chunk => chunks.push(chunk));
            res.on("end", () => resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks) }));
            res.on("error", reject);
        });
        req.on("timeout", () => req.destroy(new Error("request has timed out")));
        req.on("error", reject);
        req.end(body);
    });
}

function invertString(text: string): Buffer {
    const buffer = Buffer.alloc(16);
    buffer.write(text, "ascii");
    for (let i = 0; i < buffer.length; i++) {
        buffer[i] ^= 0xFF;
    }
    return buffer;
}

function toHex(buffer: Buffer): string {
    return buffer.toString("hex").toUpperCase();
}

function md5(...buffers: Buffer[]): Buffer {
    return createHash("md5").update(Buffer.concat(buffers)).digest();
}

function encrypt(algorithm: "aes-128-cbc" | "aes-128-ecb", key: Buffer, iv: Buffer, data: Buffer): Buffer {
    const cipher = createCipheriv(algorithm, key, iv).setAutoPadding(false);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}

function decrypt(algorithm: "aes-128-cbc" | "aes-128-ecb", key: Buffer, iv: Buffer, data: Buffer): Buffer {
    const decipher = createDecipheriv(algorithm, key, iv).setAutoPadding(false);
    return Buffer.concat([decipher.update(data), decipher.final()]);
}
