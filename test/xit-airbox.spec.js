const { describe, it } = require("node:test");
const assert = require("assert");
const crypto = require("crypto");
const { TsCrc32 } = require("@chinachu/aribts");

const { ATD1Decoder, decodeEPG } = require("../lib/Mirakurun/XitAirBox");

const hex = str => Buffer.from(str.replace(/\s+/g, ""), "hex");

// test vectors from the protocol specification
const pairingKey = hex("303132333435363738393A3B3C3D3E3F");
const uid = hex("404142434445464748494A4B4C4D4E4F");
const path = "/live.TB.587.1234.0101.at1&resolution=1280x720&videoBitrate=6000,6000,5500,5000&dualMono=LL";
const header = hex(`
    470000000000000001000000FEB7D03D318992B01F8AEF31E531269FF120A8EE
    2E00FFA371FB48CA4CFE9AEAD0AB9D29AB3211C0B1B0D203AC0333B0DE8B8D26
    1585CEF25E3C9DA20C0A50447746674159853FBE4FE6E9B62DD753EC524E8BE9
    96762142E312F54DC20522EDCD6279A6E34B28F9DC0C441B4A72A61EAB261E06
    10E9E39821A23E82476894322AF2A2CDF8E74E6FBCDDD187CB4ED65A01CBE4D1
    C100B3CC8F5D8DB749E5A59A6E79D1D1C43AA0A5D14E32B16DB98B36
`);
const bodyKey = hex("CC2B391632D732F85FEEA70AF57EEF4B");

function encryptBody(data) {
    const cipher = crypto.createCipheriv("aes-128-cbc", bodyKey, uid).setAutoPadding(false);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}

function createPacket(pid, payload, isStart) {
    const packet = Buffer.alloc(188, 0xFF);
    packet[0] = 0x47;
    packet.writeUInt16BE((isStart ? 0x4000 : 0) | pid, 1);
    packet[3] = 0x10;
    payload.copy(packet, 4);
    return packet;
}

function createSectionPackets(pid, section) {
    const data = Buffer.concat([Buffer.from([0]), section]); // pointer_field
    const packets = [];
    for (let offset = 0; offset < data.length; offset += 184) {
        packets.push(createPacket(pid, data.subarray(offset, offset + 184), offset === 0));
    }
    return packets;
}

function withCRC(section) {
    const crc = Buffer.alloc(4);
    crc.writeInt32BE(TsCrc32.calc(section));
    return Buffer.concat([section, crc]);
}

function decode(chunks) {
    return new Promise((resolve, reject) => {
        const decoder = new ATD1Decoder(path, pairingKey, uid);
        const output = [];
        let session = null;
        decoder.on("session", s => session = s);
        decoder.on("data", data => output.push(data));
        decoder.on("error", reject);
        decoder.on("end", () => resolve({ session, output: Buffer.concat(output) }));
        for (const chunk of chunks) {
            decoder.write(chunk);
        }
        decoder.end();
    });
}

function split(data, size) {
    const chunks = [];
    for (let offset = 0; offset < data.length; offset += size) {
        chunks.push(data.subarray(offset, offset + size));
    }
    return chunks;
}

describe("[xit-airbox.spec] XitAirBox.ts: ATD1Decoder", () => {
    it("decrypts the header and the stream", async () => {
        const nullPackets = Buffer.concat(Array.from({ length: 4 }, () => createPacket(0x1FFF, Buffer.alloc(0), false)));
        const body = encryptBody(nullPackets);
        assert.strictEqual(body.subarray(0, 16).toString("hex").toUpperCase(), "CB21CF2E1A6E55104F37FF9F629C5297");

        const { session, output } = await decode(split(Buffer.concat([header, body]), 100));

        assert.strictEqual(session.serverNonce.toString("hex").toUpperCase(), "505152535455565758595A5B5C5D5E5F");
        assert.strictEqual(session.sequence, 0x01020304);
        assert.deepStrictEqual(output, nullPackets);
    });

    it("fails if the header checksum mismatches", async () => {
        const broken = Buffer.from(header);
        broken[100] ^= 0xFF;

        await assert.rejects(decode([broken]), /checksum mismatch/);
    });

    it("rewrites PMT to point the actual video/audio PIDs", async () => {
        const pat = withCRC(hex("00b0117fe2dd00000410e1100000e01f"));
        // the PMT sent by the device (the ES loop is extended to span 2 packets)
        const esLoop = hex("1be111f006520100c8014b11e112f00352011006e116f008520130fd0300083d").toString("hex") +
            "0de511f00a520140fd05000c1fffbf".repeat(10);
        const pmtBody = hex("0410f10000e100f00909040005e101de01ef" + esLoop);
        const pmt = Buffer.concat([hex("02b000"), pmtBody]);
        pmt.writeUInt16BE(0xB000 | (pmtBody.length + 4), 1);

        const packets = [
            ...createSectionPackets(0x0000, pat),
            ...createSectionPackets(0x0110, withCRC(pmt)),
            createPacket(0x0002, Buffer.alloc(0), true)
        ];
        assert.strictEqual(packets.length, 4);

        const { output } = await decode(split(Buffer.concat([header, encryptBody(Buffer.concat(packets))]), 1000));
        const outputPackets = split(output, 188);
        assert.strictEqual(outputPackets.length, 4);

        const section = Buffer.concat([outputPackets[1].subarray(5), outputPackets[2].subarray(4)]).subarray(0, pmt.length + 4);
        assert.strictEqual(TsCrc32.calc(section), 0);

        const streams = [];
        for (let i = 12 + (section.readUInt16BE(10) & 0x0FFF); i + 5 <= section.length - 4; i += 5 + (section.readUInt16BE(i + 3) & 0x0FFF)) {
            streams.push([section[i], section.readUInt16BE(i + 1) & 0x1FFF]);
        }
        assert.deepStrictEqual(streams.slice(0, 4), [[0x1B, 0x0002], [0x0F, 0x0003], [0x06, 0x0116], [0x0D, 0x0511]]);
        assert.strictEqual(section.readUInt16BE(8) & 0x1FFF, 0x0100);
    });
});

describe("[xit-airbox.spec] XitAirBox.ts: decodeEPG()", () => {
    function scramble(data) {
        const scrambled = Buffer.concat([crypto.randomBytes(16), Buffer.alloc(data.length)]);
        for (let i = 0; i < data.length; i++) {
            scrambled[i + 16] = data[i] ^ scrambled[i];
        }
        return scrambled;
    }

    function createRecord(serviceId, eventId, counts, extra) {
        const record = Buffer.alloc(22);
        record.writeUInt32BE(1700000000, 0);
        record.writeUInt32BE(60, 4);
        record.writeUInt16BE(serviceId, 8);
        record.writeUInt16BE(eventId, 10);
        Buffer.from(counts).copy(record, 12);
        return Buffer.concat([record, extra]);
    }

    const epg = scramble(Buffer.concat([
        hex("AAAAAAAA 0000123400000000 00000000"),
        hex("BBBBBBBB 000012340101000000000000 000012340102000000000000"),
        hex("CCCCCCCC"),
        createRecord(0x0101, 0x0202, [2, 2, 0, 2, 1, 1, 0, 0, 1, 0], Buffer.concat([
            hex("01010202 01020202"),
            hex("b300"),
            hex("031000010207006a706e00000000"),
            Buffer.from([8, 0]),
            hex("0e504c4159455253"),
            hex("52ffff ffffffff 01020100")
        ])),
        createRecord(0x0102, 0x0202, [2, 2, 0, 1, 0, 0, 0, 0, 0, 0], hex("01010202")),
        createRecord(0x0102, 0x0000, [2, 0, 0, 0, 0, 0, 0, 0, 0, 0], Buffer.alloc(0))
    ]));

    it("decodes programs", () => {
        const programs = decodeEPG(epg, 0x1234);

        assert.strictEqual(programs.length, 2);
        assert.deepStrictEqual(programs[0], {
            id: 46600025700514,
            eventId: 0x0202,
            serviceId: 0x0101,
            networkId: 0x1234,
            startAt: 1699967600000,
            duration: 60000,
            isFree: true,
            relatedItems: [{ type: "shared", networkId: 0x1234, serviceId: 0x0102, eventId: 0x0202 }],
            video: { type: "mpeg2", resolution: "1080i", streamContent: 1, componentType: 0xB3 },
            audios: [{ componentType: 0x03, componentTag: 0x10, isMain: true, samplingRate: 48000, langs: ["jpn"] }],
            name: "ＰＬＡＹＥＲＳ",
            description: "",
            genres: [{ lv1: 5, lv2: 2, un1: 15, un2: 15 }]
        });
        assert.deepStrictEqual(programs[1].relatedItems, [{ type: "shared", networkId: 0x1234, serviceId: 0x0101, eventId: 0x0202 }]);
    });

    it("ignores programs of other networks", () => {
        assert.deepStrictEqual(decodeEPG(epg, 0x4321), []);
    });

    it("fails with invalid data", () => {
        assert.throws(() => decodeEPG(crypto.randomBytes(64), 0x1234), /invalid EPG data/);
    });
});
