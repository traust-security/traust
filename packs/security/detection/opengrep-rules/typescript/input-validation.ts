import * as yaml from "js-yaml";
const serialize = require("node-serialize");
const libxmljs = require("libxmljs");

export function restore(cookie: string) {
  // ruleid: traust-ts-input-validation-unsafe-deserialization
  const session = serialize.unserialize(Buffer.from(cookie, "base64").toString());
  // ruleid: traust-ts-input-validation-unsafe-deserialization
  const doc = yaml.load(body, { schema: yaml.DEFAULT_FULL_SCHEMA });
  // ok: traust-ts-input-validation-unsafe-deserialization
  const plain = yaml.load(body);
  // ok: traust-ts-input-validation-unsafe-deserialization
  const parsed = JSON.parse(cookie);
  return [session, doc, plain, parsed];
}

export function importFeed(xml: string) {
  // ruleid: traust-ts-input-validation-xxe-noent
  const doc = libxmljs.parseXml(xml, { noent: true });
  // ok: traust-ts-input-validation-xxe-noent
  const safe = libxmljs.parseXml(xml, { noent: false });
  return [doc, safe];
}
