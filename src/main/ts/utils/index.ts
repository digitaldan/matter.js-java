export function toUint8(javaByteArray: Array<number>): Uint8Array {
    return new Uint8Array(javaByteArray);
}
export function toInt8(uint8Array: Uint8Array): any {
    return new Int8Array(uint8Array);
}

export * from "./CommandLine";