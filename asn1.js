/**
 * Copyright © 2024 FirstTimeEZ
 * https://github.com/FirstTimeEZ
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export const TAGS = {
    BOOLEAN: 0x01,                  // BOOLEAN
    INTEGER: 0x02,                  // INTEGER
    BIT_STRING: 0x03,               // BIT STRING
    OCTET_STRING: 0x04,             // OCTET STRING
    NULL: 0x05,                     // NULL
    OBJECT_IDENTIFIER: 0x06,        // OBJECT IDENTIFIER
    REAL: 0x09,                     // REAL
    ENUMERATED: 0x0A,               // ENUMERATED
    UTF8String: 0x0C,               // UTF8String
    SEQUENCE: 0x30,                 // SEQUENCE
    SET: 0x31,                      // SET
    PRINTABLE_STRING: 0x13,         // PrintableString
    IA5String: 0x16,                // IA5String
    T61String: 0x14,                // T61String
    GRAPHIC_STRING: 0x19,           // GraphicString
    VIDEOTEX_STRING: 0x1A,          // VideotexString
    GENERALIZED_TIME: 0x18,         // GeneralizedTime
    UTC_TIME: 0x17,                 // UTCTime
    BMP_STRING: 0x1E,               // BMPString
    ZERO: 0x00,                     // Zero
    CONTEXT_SPECIFIC_ZERO: 0xA0,    // ContextSpecificZero
    CONTEXT_SPECIFIC_THREE: 0xA3    // ExtensionsContext
};

export function encodeDERBitString(data) {
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    return Buffer.concat([
        Buffer.from([0x03]),
        encodeDERLength(buffer.length + 1),
        Buffer.from([TAGS.ZERO]),
        buffer
    ]);
}

export function encodeDERAttribute(oid, value) {
    const oidBuffer = encodeDERObjectIdentifier(oid);
    const valueBuffer = Buffer.from(value, 'utf8');
    const stringValue = Buffer.concat([
        Buffer.from([TAGS.UTF8String]),
        encodeDERLength(valueBuffer.length),
        valueBuffer
    ]);

    return encodeDERSequence([
        oidBuffer,
        stringValue
    ]);
}

export function encodeDERSequence(elements) {
    const totalLength = elements.reduce((sum, el) => sum + el.length, 0);
    return Buffer.concat([
        Buffer.from([TAGS.SEQUENCE]),
        encodeDERLength(totalLength),
        ...elements
    ]);
}

export function encodeDERSet(elements) {
    const totalLength = elements.reduce((sum, el) => sum + el.length, 0);
    return Buffer.concat([
        Buffer.from([TAGS.SET]),
        encodeDERLength(totalLength),
        ...elements
    ]);
}

export function encodeDERContextSpecific(tag, value) {
    return Buffer.concat([
        Buffer.from([TAGS.CONTEXT_SPECIFIC_ZERO | tag]),
        encodeDERLength(value.length),
        value
    ]);
}

export function encodeDERLength(length) {
    if (length < 128) {
        return Buffer.from([length]);
    }

    const bytes = [];
    let temp = length;
    while (temp > 0) {
        bytes.unshift(temp & 0xFF);
        temp = temp >> 8;
    }
    bytes.unshift(bytes.length | 0x80);
    return Buffer.from(bytes);
}

export function encodeDERObjectIdentifier(oid) {
    const numbers = oid.split('.').map(Number);
    if (numbers.length < 2) {
        throw new Error('Invalid OID: must have at least 2 components');
    }

    const first = numbers[0] * 40 + numbers[1];
    const encoded = [first];

    for (let i = 2; i < numbers.length; i++) {
        let number = numbers[i];
        if (number < 0) {
            throw new Error('Invalid OID: negative numbers not allowed');
        }

        if (number < 128) {
            encoded.push(number);
        } else {
            const bytes = [];
            while (number > 0) {
                bytes.unshift((number & 0x7F) | (bytes.length ? 0x80 : 0));
                number = number >> 7;
            }
            encoded.push(...bytes);
        }
    }

    return Buffer.concat([
        Buffer.from([TAGS.OBJECT_IDENTIFIER]),
        Buffer.from([encoded.length]),
        Buffer.from(encoded)
    ]);
}

export function encodeDEROctetString(data) {
    return Buffer.concat([
        Buffer.from([TAGS.OCTET_STRING]),
        encodeDERLength(data.length),
        data
    ]);
}

export function readDERLength(buffer) {
    if (buffer[0] < 128) return buffer[0];

    const numBytes = buffer[0] & 0x7F;
    let length = 0;

    for (let i = 1; i <= numBytes; i++) {
        length = (length << 8) | buffer[i];
    }

    return length;
}

export function skipDERLength(buffer) {
    if (buffer[0] < 128) return 1;
    return (buffer[0] & 0x7F) + 1;
}

export function decodeSerialNumber(certBuffer) {
    if (certBuffer[0] != 0x30) {
        return undefined;
    }

    let offset = 1;

    const seq1 = readASN1Length(certBuffer, offset);

    if (seq1 === undefined) {
        return undefined;
    }

    offset += seq1.lengthOfLength + 2;

    const seq2 = readASN1Length(certBuffer, offset);

    if (seq2 === undefined) {
        return undefined;
    }

    offset += seq2.lengthOfLength + 2;

    if (certBuffer[offset - 1] !== TAGS.CONTEXT_SPECIFIC_ZERO) {
        return undefined;
    }

    offset += certBuffer[offset] + 2;

    if (certBuffer[offset - 1] != 0x02) {
        return undefined;
    }

    return certBuffer.slice(offset + 1, offset + certBuffer[offset] + 1).toString('hex');
}

export function decodeAKI(certBuffer) {
    if (certBuffer[0] != TAGS.SEQUENCE) { // Cert Starts with SEQUENCE
        return undefined;
    }

    let offset = 0;

    const certificate = readOuterSequence(certBuffer, 0);

    if (certificate === undefined) {
        return undefined;
    }

    const tbsCertficate = readOuterSequence(certificate[0], 0);

    if (tbsCertficate === undefined) {
        return undefined;
    }

    if (tbsCertficate[0][0] !== TAGS.CONTEXT_SPECIFIC_ZERO) { // Version should be the first element
        return undefined;
    }
    else {
        offset++;
    }

    const versionLen = readASN1Length(tbsCertficate[0], offset);  // skip version length;

    offset += versionLen.length + versionLen.lengthOfLength;

    if (tbsCertficate[0][offset] !== TAGS.INTEGER) {
        return undefined;
    }
    else {
        offset++;
    }

    const serialNumberLen = readASN1Length(tbsCertficate[0], offset);  // skip serial number;

    offset += serialNumberLen.length + serialNumberLen.lengthOfLength;

    if (tbsCertficate[0][offset] !== TAGS.SEQUENCE) {
        console.log("Expected a sequence after the serial number");
        return undefined;
    }
    else {
        offset++;
    }

    while (tbsCertficate[0][offset - 1] !== TAGS.CONTEXT_SPECIFIC_THREE) { // find extensions by looking for CONTEXT_SPECIFIC_THREE
        const skipSequences = readASN1Length(tbsCertficate[0], offset);

        if (skipSequences === undefined) {
            return undefined;
        }
        else {
            offset++;
            offset += skipSequences.length + skipSequences.lengthOfLength;
        }
    }

    if (tbsCertficate[0][offset - 1] !== TAGS.CONTEXT_SPECIFIC_THREE) {
        return undefined;
    }

    const extensions = readASN1Length(tbsCertficate[0], offset); // extensions [3] (1 elem)

    if (extensions === undefined) {
        return undefined;
    }

    offset += extensions.lengthOfLength + 2;

    const innerExtensions = readSequenceParts(readOuterSequence(tbsCertficate[0].slice(offset - 1, offset + extensions.length))[0]); // Extensions SEQUENCE (9 elem)

    let rawAKI = null;

    for (let index = 0; index < innerExtensions.length; index++) {
        bytesToOID(innerExtensions[index]) === "2.5.29.35" && (rawAKI = innerExtensions[index]);
    }

    if (rawAKI === null) {
        return undefined;
    }

    return readOuterSequence(rawAKI.slice(rawAKI[1] + 4))[0].slice(1).toString('hex'); // 2.5.29.35 (4bytes) // SEQUENCE extnValue OCTET STRING (4 byte) 301680 // [0] (20 byte) FC46D101435FBB7BA63D3068AE11BAE0BC6DC9D3
}

export function pemToBuffer(pemCertificate) {
    const base64Cert = pemCertificate
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s+/g, '');

    return Buffer.from(base64Cert, 'base64');
}

export function readASN1Length(buffer, offset) {
    if (offset >= buffer.length) {
        return undefined;
    }

    const lengthByte = buffer[offset];

    if (lengthByte < 0x80) {
        return { length: lengthByte, lengthOfLength: 1 };
    }

    const lengthOfLength = lengthByte & 0x7F;
    if (lengthOfLength === 0) {
        return undefined;
    }

    if (offset + lengthOfLength >= buffer.length) {
        return undefined;
    }

    let length = 0;
    for (let i = 1; i <= lengthOfLength; i++) {
        length = (length << 8) | buffer[offset + i];
    }

    return { length: length, lengthOfLength: lengthOfLength };
}

export function bytesToOID(byteArray) {
    if (byteArray[0] !== 0x06) {
        return undefined;
    }

    const length = byteArray[1];

    const oidBytes = byteArray.slice(2, 2 + length);

    const oidComponents = [];

    const firstByte = oidBytes[0];

    const firstComponent = Math.floor(firstByte / 40);
    const secondComponent = firstByte % 40;

    oidComponents.push(firstComponent.toString());
    oidComponents.push(secondComponent.toString());

    let currentComponent = 0;
    for (let i = 1; i < oidBytes.length; i++) {
        currentComponent = (currentComponent << 7) | (oidBytes[i] & 0x7F);
        if ((oidBytes[i] & 0x80) === 0) {
            oidComponents.push(currentComponent.toString());
            currentComponent = 0;
        }
    }

    return oidComponents.join('.');
}

export function readOuterSequence(certBuffer) {
    const parts = [];

    let start = 1;

    const seq1 = readASN1Length(certBuffer, start);

    if (seq1 != undefined) {

        start += start + seq1.lengthOfLength;

        let v = certBuffer.slice(start, start + seq1.length);

        start += seq1.length + 2;

        parts.push(v);
    }

    return parts;
}

export function readSequenceParts(innerSequence) {
    const parts = [];

    let start = 1;

    while (start < innerSequence.length) {
        const seq1 = readASN1Length(innerSequence, start);
        if (seq1 != undefined) {
            start += seq1.lengthOfLength;

            let v = innerSequence.slice(start, start + seq1.length);

            start += seq1.length + 1;

            parts.push(v);
        }
        else {
            break;
        }
    }

    return parts;
}