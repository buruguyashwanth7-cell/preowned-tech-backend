// tests/authorization.test.js
// Tests for roles, verified accounts, ownership, private conversations,
// suspended listings, public responses and the AI gate.

const mongoose = require("mongoose");
const User = require("../src/models/User");
const { containsSensitiveKeys } = require("../src/utils/serializers");
const { connectTestDB, clearDB, disconnectTestDB } = require("./helpers/db");
const { createClient, newUser } = require("./helpers/client");
const {
  app: standInApp,
  Listing,
  Conversation,
  ViewingRequest,
} = require("./helpers/standInApp");

beforeAll(async () => {
  process.env.DISABLE_RATE_LIMIT = "1"; // rate limits are tested in their own file
  await connectTestDB();
}, 300000);

afterEach(async () => {
  await clearDB();
});

afterAll(async () => {
  delete process.env.DISABLE_RATE_LIMIT;
  await disconnectTestDB();
});

// Creates a user, verifies the email (unless told not to), logs in.
// Returns { client, id, email }. A "moderator" is made by changing the role in the database,
// because nobody can register as one.
async function makePerson({ role = "buyer", verified = true } = {}) {
  const data = newUser({ role: role === "moderator" ? "buyer" : role });
  const client = await createClient(standInApp);

  const reg = await client.post("/api/auth/register", data);
  if (verified) {
    await client.post("/api/auth/verify-email", {
      token: reg.body.devVerificationToken,
    });
  }
  if (role === "moderator") {
    await User.updateOne({ email: data.email }, { $set: { role: "moderator" } });
  }

  const login = await client.post("/api/auth/login", {
    email: data.email,
    password: data.password,
  });
  return { client, id: login.body.user.id, email: data.email };
}

async function anonymous() {
  return createClient(standInApp);
}

function makeListing(sellerId, extra = {}) {
  return Listing.create({
    seller: sellerId,
    title: "Used laptop",
    price: 300,
    serialNumber: "SN-123",
    receiptUrl: "http://example.com/receipt.png",
    internalNotes: "keep this secret",
    ...extra,
  });
}

describe("public listing responses", () => {
  test("hide serial numbers, receipts, notes and the seller's email", async () => {
    const seller = await makePerson({ role: "seller" });
    const listing = await makeListing(seller.id);

    const res = await (await anonymous()).get(`/api/standin/listings/${listing.id}`);

    expect(res.status).toBe(200);
    expect(res.body.listing.title).toBe("Used laptop");
    expect(res.body.listing).not.toHaveProperty("serialNumber");
    expect(res.body.listing).not.toHaveProperty("receiptUrl");
    expect(res.body.listing).not.toHaveProperty("internalNotes");
    expect(Object.keys(res.body.listing.seller).sort()).toEqual(["id", "name"]);
    expect(containsSensitiveKeys(res.body)).toBe(false);
    expect(JSON.stringify(res.body)).not.toContain(seller.email);
  });

  test("an unknown listing returns 404", async () => {
    const res = await (await anonymous()).get(
      `/api/standin/listings/${new mongoose.Types.ObjectId()}`
    );
    expect(res.status).toBe(404);
  });
});

describe("creating listings", () => {
  test("needs a login", async () => {
    const res = await (await anonymous()).post("/api/standin/listings", { title: "x" });
    expect(res.status).toBe(401);
  });

  test("an unverified seller is blocked", async () => {
    const seller = await makePerson({ role: "seller", verified: false });
    const res = await seller.client.post("/api/standin/listings", { title: "x" });
    expect(res.status).toBe(403);
    expect(await Listing.countDocuments()).toBe(0);
  });

  test("a buyer is blocked", async () => {
    const buyer = await makePerson({ role: "buyer" });
    const res = await buyer.client.post("/api/standin/listings", { title: "x" });
    expect(res.status).toBe(403);
    expect(await Listing.countDocuments()).toBe(0);
  });

  test("a verified seller can create one, and is always the owner", async () => {
    const seller = await makePerson({ role: "seller" });
    const other = await makePerson({ role: "seller" });

    const res = await seller.client.post("/api/standin/listings", {
      title: "Phone",
      price: 100,
      serialNumber: "SN-9",
      seller: other.id, // an attempt to create it in someone else's name
    });

    expect(res.status).toBe(201);
    const saved = await Listing.findById(res.body.listing.id);
    expect(String(saved.seller)).toBe(seller.id);
  });
});

describe("private listing details (ownership)", () => {
  test("the owner sees serial number and receipt, but not internal notes", async () => {
    const seller = await makePerson({ role: "seller" });
    const listing = await makeListing(seller.id);

    const res = await seller.client.get(`/api/standin/listings/${listing.id}/private`);
    expect(res.status).toBe(200);
    expect(res.body.listing.serialNumber).toBe("SN-123");
    expect(res.body.listing.receiptUrl).toBeDefined();
    expect(res.body.listing).not.toHaveProperty("internalNotes");
  });

  test("another seller gets 404", async () => {
    const owner = await makePerson({ role: "seller" });
    const other = await makePerson({ role: "seller" });
    const listing = await makeListing(owner.id);

    const res = await other.client.get(`/api/standin/listings/${listing.id}/private`);
    expect(res.status).toBe(404);
  });

  test("a buyer gets 404", async () => {
    const owner = await makePerson({ role: "seller" });
    const buyer = await makePerson({ role: "buyer" });
    const listing = await makeListing(owner.id);

    const res = await buyer.client.get(`/api/standin/listings/${listing.id}/private`);
    expect(res.status).toBe(404);
  });

  test("needs a login", async () => {
    const owner = await makePerson({ role: "seller" });
    const listing = await makeListing(owner.id);

    const res = await (await anonymous()).get(`/api/standin/listings/${listing.id}/private`);
    expect(res.status).toBe(401);
  });

  test("an unverified owner is blocked", async () => {
    const owner = await makePerson({ role: "seller", verified: false });
    const listing = await makeListing(owner.id);

    const res = await owner.client.get(`/api/standin/listings/${listing.id}/private`);
    expect(res.status).toBe(403);
  });

  test("a moderator may look", async () => {
    const owner = await makePerson({ role: "seller" });
    const moderator = await makePerson({ role: "moderator" });
    const listing = await makeListing(owner.id);

    const res = await moderator.client.get(`/api/standin/listings/${listing.id}/private`);
    expect(res.status).toBe(200);
  });

  test("an unknown listing returns 404", async () => {
    const owner = await makePerson({ role: "seller" });
    const res = await owner.client.get(
      `/api/standin/listings/${new mongoose.Types.ObjectId()}/private`
    );
    expect(res.status).toBe(404);
  });

  test("an invalid id returns 404, not an error", async () => {
    const owner = await makePerson({ role: "seller" });
    const res = await owner.client.get("/api/standin/listings/abc/private");
    expect(res.status).toBe(404);
  });
});

describe("private conversations", () => {
  async function setup({ buyerVerified = true } = {}) {
    const buyer = await makePerson({ role: "buyer", verified: buyerVerified });
    const seller = await makePerson({ role: "seller" });
    const convo = await Conversation.create({
      buyer: buyer.id,
      seller: seller.id,
      messages: ["hello", "is it still available?"],
      internalFlag: "do-not-share",
    });
    return { buyer, seller, convo };
  }

  test("the buyer in it can read it", async () => {
    const { buyer, convo } = await setup();
    const res = await buyer.client.get(`/api/standin/conversations/${convo.id}`);
    expect(res.status).toBe(200);
    expect(res.body.messages).toEqual(["hello", "is it still available?"]);
  });

  test("the seller in it can read it", async () => {
    const { seller, convo } = await setup();
    const res = await seller.client.get(`/api/standin/conversations/${convo.id}`);
    expect(res.status).toBe(200);
  });

  test("a stranger gets 404", async () => {
    const { convo } = await setup();
    const stranger = await makePerson({ role: "buyer" });
    const res = await stranger.client.get(`/api/standin/conversations/${convo.id}`);
    expect(res.status).toBe(404);
  });

  test("an unverified participant is blocked", async () => {
    const { buyer, convo } = await setup({ buyerVerified: false });
    const res = await buyer.client.get(`/api/standin/conversations/${convo.id}`);
    expect(res.status).toBe(403);
  });

  test("needs a login", async () => {
    const { convo } = await setup();
    const res = await (await anonymous()).get(`/api/standin/conversations/${convo.id}`);
    expect(res.status).toBe(401);
  });
});

describe("viewing requests", () => {
  const url = (listing) => `/api/standin/listings/${listing.id}/viewing-requests`;

  test("a verified buyer can ask to view an active listing", async () => {
    const seller = await makePerson({ role: "seller" });
    const buyer = await makePerson({ role: "buyer" });
    const listing = await makeListing(seller.id);

    const res = await buyer.client.post(url(listing));
    expect(res.status).toBe(201);
    expect(await ViewingRequest.countDocuments()).toBe(1);
  });

  test.each([{ status: "suspended" }, { isSuspended: true }])(
    "a suspended listing (%o) cannot get new viewing requests",
    async (suspendedFields) => {
      const seller = await makePerson({ role: "seller" });
      const buyer = await makePerson({ role: "buyer" });
      const listing = await makeListing(seller.id, suspendedFields);

      const res = await buyer.client.post(url(listing));
      expect(res.status).toBe(403);
      expect(await ViewingRequest.countDocuments()).toBe(0);
    }
  );

  test("an unverified buyer is blocked", async () => {
    const seller = await makePerson({ role: "seller" });
    const buyer = await makePerson({ role: "buyer", verified: false });
    const listing = await makeListing(seller.id);

    const res = await buyer.client.post(url(listing));
    expect(res.status).toBe(403);
    expect(await ViewingRequest.countDocuments()).toBe(0);
  });

  test("a seller cannot make viewing requests", async () => {
    const seller = await makePerson({ role: "seller" });
    const otherSeller = await makePerson({ role: "seller" });
    const listing = await makeListing(seller.id);

    const res = await otherSeller.client.post(url(listing));
    expect(res.status).toBe(403);
  });

  test("needs a login", async () => {
    const seller = await makePerson({ role: "seller" });
    const listing = await makeListing(seller.id);

    const res = await (await anonymous()).post(url(listing));
    expect(res.status).toBe(401);
  });

  test("an unknown listing returns 404", async () => {
    const buyer = await makePerson({ role: "buyer" });
    const res = await buyer.client.post(
      `/api/standin/listings/${new mongoose.Types.ObjectId()}/viewing-requests`
    );
    expect(res.status).toBe(404);
  });

  test("the listing's owner can see how many requests it has", async () => {
    const seller = await makePerson({ role: "seller" });
    const buyer = await makePerson({ role: "buyer" });
    const listing = await makeListing(seller.id);
    await buyer.client.post(url(listing));

    const res = await seller.client.get(url(listing));
    expect(res.status).toBe(200);
    expect(res.body.count).toBe(1);
  });

  test("another seller cannot see them", async () => {
    const seller = await makePerson({ role: "seller" });
    const otherSeller = await makePerson({ role: "seller" });
    const listing = await makeListing(seller.id);

    const res = await otherSeller.client.get(url(listing));
    expect(res.status).toBe(404);
  });
});

describe("the AI gate", () => {
  async function setup({ buyerVerified = true } = {}) {
    const buyer = await makePerson({ role: "buyer", verified: buyerVerified });
    const seller = await makePerson({ role: "seller" });
    const convo = await Conversation.create({
      buyer: buyer.id,
      seller: seller.id,
      messages: ["hello", "is it still available?"],
      internalFlag: "do-not-share",
    });
    return { buyer, convo, path: `/api/standin/conversations/${convo.id}/ai-summary` };
  }

  test("a participant gets only the allowed fields", async () => {
    const { buyer, path } = await setup();
    const res = await buyer.client.post(path);

    expect(res.status).toBe(200);
    expect(Object.keys(res.body.aiInput).sort()).toEqual(["id", "messages"]);
    expect(res.body.aiInput.messages).toEqual(["hello", "is it still available?"]);
    expect(JSON.stringify(res.body)).not.toContain("do-not-share");
  });

  test("a stranger gets 404 and nothing is passed on", async () => {
    const { path } = await setup();
    const stranger = await makePerson({ role: "buyer" });

    const res = await stranger.client.post(path);
    expect(res.status).toBe(404);
    expect(res.body).not.toHaveProperty("aiInput");
  });

  test("an unverified user is blocked", async () => {
    const { buyer, path } = await setup({ buyerVerified: false });
    const res = await buyer.client.post(path);
    expect(res.status).toBe(403);
    expect(res.body).not.toHaveProperty("aiInput");
  });

  test("needs a login", async () => {
    const { path } = await setup();
    const res = await (await anonymous()).post(path);
    expect(res.status).toBe(401);
  });
});