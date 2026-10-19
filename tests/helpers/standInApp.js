// tests/helpers/standInApp.js
// A small app used ONLY in tests. It uses your REAL sessions, CSRF, login routes
// and authorization middleware, plus STAND-IN listing / conversation / viewing
// request routes. Your teammates will write the real ones later.

const express = require("express");
const mongoose = require("mongoose");
const { sessionMiddleware } = require("../../src/config/session");
const { verifyCsrf } = require("../../src/middleware/csrf");
const authRoutes = require("../../src/routes/authRoutes");
const { requireAuth } = require("../../src/middleware/auth");
const {
  requireVerified,
  requireRole,
  requireOwner,
  requireParticipant,
  requireListingActive,
} = require("../../src/middleware/authorize");
const { toPublicListing, toOwnerListing, makeSerializer } = require("../../src/utils/serializers");
const { authorizeForAI, isParticipant } = require("../../src/services/aiAccess");

const { Schema } = mongoose;

// ---- Stand-in models (test only) ----
const Listing =
  mongoose.models.StandInListing ||
  mongoose.model(
    "StandInListing",
    new Schema(
      {
        seller: { type: Schema.Types.ObjectId, ref: "User", required: true },
        title: String,
        price: Number,
        status: { type: String, default: "active" },
        isSuspended: Boolean,
        serialNumber: String,
        receiptUrl: String,
        internalNotes: String,
      },
      { timestamps: true }
    )
  );

const Conversation =
  mongoose.models.StandInConversation ||
  mongoose.model(
    "StandInConversation",
    new Schema({
      buyer: { type: Schema.Types.ObjectId, ref: "User", required: true },
      seller: { type: Schema.Types.ObjectId, ref: "User", required: true },
      messages: [String],
      internalFlag: String,
    })
  );

const ViewingRequest =
  mongoose.models.StandInViewingRequest ||
  mongoose.model(
    "StandInViewingRequest",
    new Schema({
      listing: { type: Schema.Types.ObjectId, required: true },
      buyer: { type: Schema.Types.ObjectId, required: true },
    })
  );

// ---- Stand-in app ----
const app = express();
app.use(express.json({ limit: "10kb" }));
app.use(sessionMiddleware);
app.use("/api", verifyCsrf);
app.use("/api/auth", authRoutes);

// Finds a record by id. An invalid id simply means "not found".
const findById = (Model, id) => (mongoose.isValidObjectId(id) ? Model.findById(id) : null);
const loadListing = (req) => findById(Listing, req.params.id);
const loadConversation = (req) => findById(Conversation, req.params.id);

// Anyone (even not logged in) may see the PUBLIC view of a listing.
app.get("/api/standin/listings/:id", async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(404).json({ message: "Not found" });
  }
  const listing = await Listing.findById(req.params.id).populate("seller", "name");
  if (!listing) return res.status(404).json({ message: "Not found" });
  res.json({ listing: toPublicListing(listing) });
});

// Only verified sellers may create a listing. The seller is ALWAYS the logged-in user.
app.post(
  "/api/standin/listings",
  requireAuth,
  requireVerified,
  requireRole("seller"),
  async (req, res) => {
    const { title, price, serialNumber, receiptUrl } = req.body;
    const listing = await Listing.create({
      seller: req.user.id,
      title,
      price,
      serialNumber,
      receiptUrl,
    });
    res.status(201).json({ listing: toOwnerListing(listing) });
  }
);

// The owner (or a moderator/admin) may see the private details.
app.get(
  "/api/standin/listings/:id/private",
  requireAuth,
  requireVerified,
  requireOwner({
    load: loadListing,
    ownerField: "seller",
    allowRoles: ["moderator", "admin"],
    resourceKey: "listing",
  }),
  (req, res) => res.json({ listing: toOwnerListing(req.listing) })
);

// Only verified buyers may ask for a viewing, and never on a suspended listing.
app.post(
  "/api/standin/listings/:id/viewing-requests",
  requireAuth,
  requireVerified,
  requireRole("buyer"),
  requireListingActive({ load: loadListing }),
  async (req, res) => {
    const request = await ViewingRequest.create({
      listing: req.listing._id,
      buyer: req.user.id,
    });
    res.status(201).json({ viewingRequest: { id: request.id } });
  }
);

// Only the listing's owner may see the requests made on it.
app.get(
  "/api/standin/listings/:id/viewing-requests",
  requireAuth,
  requireVerified,
  requireOwner({ load: loadListing, ownerField: "seller", resourceKey: "listing" }),
  async (req, res) => {
    const items = await ViewingRequest.find({ listing: req.listing._id });
    res.json({ count: items.length });
  }
);

// Only the two people in a conversation may read it.
app.get(
  "/api/standin/conversations/:id",
  requireAuth,
  requireVerified,
  requireParticipant({
    load: loadConversation,
    participantFields: ["buyer", "seller"],
    resourceKey: "conversation",
  }),
  (req, res) => res.json({ messages: req.conversation.messages })
);

// Shows what WOULD be sent to an AI feature. The AI gate decides first.
app.post("/api/standin/conversations/:id/ai-summary", requireAuth, async (req, res) => {
  const conversation = await loadConversation(req);
  const result = await authorizeForAI({
    user: req.user,
    resource: conversation,
    canAccess: isParticipant(["buyer", "seller"]),
    serialize: makeSerializer(["messages"]),
  });

  if (!result.allowed) {
    return res.status(result.status).json({ message: result.message });
  }
  res.json({ aiInput: result.data });
});

module.exports = { app, Listing, Conversation, ViewingRequest };