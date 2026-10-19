// src/utils/serializers.js
// Decides which fields are allowed to leave the API.
// Rule: ONLY fields on an allowlist are sent. Anything else is dropped, so a
// new sensitive field can never leak by accident.

// Words that must never appear as a field name in a PUBLIC response.
// (Used by containsSensitiveKeys, mainly in tests.)
const SENSITIVE_FRAGMENTS = [
  "serial",
  "receipt",
  "passwordhash",
  "tokenhash",
  "proofofpurchase",
];
const SENSITIVE_EXACT = ["imei"];

// Turns a Mongoose document into a plain object.
function toPlain(doc) {
  return doc && typeof doc.toObject === "function" ? doc.toObject() : doc;
}

// Builds a function that keeps ONLY the listed fields (plus an "id").
function makeSerializer(allowedFields) {
  return (doc) => {
    if (!doc) return null;
    const plain = toPlain(doc);
    const out = {};

    if (plain._id || plain.id) out.id = String(plain.id || plain._id);

    for (const field of allowedFields) {
      if (plain[field] !== undefined) out[field] = plain[field];
    }
    return out;
  };
}

// A person as other people may see them: id and name only (never the email).
function toPublicUser(user) {
  if (!user) return null;
  const id = String(user._id || user.id || user);
  return user.name !== undefined ? { id, name: user.name } : { id };
}

// TODO for the listings teammate: change these names to match the real listing model.
const PUBLIC_LISTING_FIELDS = [
  "title",
  "description",
  "price",
  "category",
  "brand",
  "condition",
  "images",
  "status",
  "createdAt",
];

// The owner (seller) and moderators may also see these private fields.
const OWNER_LISTING_FIELDS = [
  ...PUBLIC_LISTING_FIELDS,
  "serialNumber",
  "receiptUrl",
  "isSuspended",
];

const publicListingFields = makeSerializer(PUBLIC_LISTING_FIELDS);
const ownerListingFields = makeSerializer(OWNER_LISTING_FIELDS);

function withSeller(serialized, listing) {
  const plain = toPlain(listing);
  if (serialized && plain.seller) serialized.seller = toPublicUser(plain.seller);
  return serialized;
}

// What ANYONE (even a visitor who isn't logged in) may see.
function toPublicListing(listing) {
  return withSeller(publicListingFields(listing), listing);
}

// What the listing's owner or a moderator may see.
function toOwnerListing(listing) {
  return withSeller(ownerListingFields(listing), listing);
}

// Returns true if any key anywhere inside the value looks sensitive.
function containsSensitiveKeys(value) {
  if (Array.isArray(value)) return value.some(containsSensitiveKeys);
  if (value === null || typeof value !== "object") return false;

  return Object.keys(value).some((key) => {
    const clean = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    const looksSensitive =
      SENSITIVE_EXACT.includes(clean) ||
      SENSITIVE_FRAGMENTS.some((fragment) => clean.includes(fragment));
    return looksSensitive || containsSensitiveKeys(value[key]);
  });
}

module.exports = {
  makeSerializer,
  toPublicUser,
  toPublicListing,
  toOwnerListing,
  containsSensitiveKeys,
  PUBLIC_LISTING_FIELDS,
  OWNER_LISTING_FIELDS,
};