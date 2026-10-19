// src/middleware/authorize.js
// Reusable permission checks. Use them AFTER requireAuth, which sets req.user.
//
// Status codes used here:
//   401 = not logged in
//   403 = logged in, but not allowed (wrong role, email not verified, suspended listing)
//   404 = "not found" for private things that belong to someone else, so we
//         don't even reveal that they exist.

// Compares two ids (works for strings, Mongo ids, and objects with an _id).
function sameId(a, b) {
  const first = a && a._id ? a._id : a;
  const second = b && b._id ? b._id : b;
  if (!first || !second) return false;
  return String(first) === String(second);
}

function notLoggedIn(res) {
  return res.status(401).json({ message: "Authentication required" });
}

// The account's email must be verified.
// Use it before creating listings, sending messages, and viewing requests.
function requireVerified(req, res, next) {
  if (!req.user) return notLoggedIn(res);

  if (!req.user.isEmailVerified) {
    return res
      .status(403)
      .json({ message: "Please verify your email address first" });
  }
  next();
}

// The user must have one of the given roles.
// Example: requireRole("seller")  or  requireRole("moderator", "admin")
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) return notLoggedIn(res);

    if (!allowedRoles.includes(req.user.role)) {
      return res
        .status(403)
        .json({ message: "You do not have permission to do this" });
    }
    next();
  };
}

// The logged-in user must be the OWNER of the thing being accessed.
//   load(req)   -> finds the thing, for example (req) => Listing.findById(req.params.id)
//   ownerField  -> which field holds the owner's id, for example "seller"
//   allowRoles  -> roles that may skip the ownership check (for example moderators)
//   resourceKey -> the loaded thing is saved on req[resourceKey] for the controller
function requireOwner({
  load,
  ownerField = "seller",
  allowRoles = [],
  resourceKey = "resource",
}) {
  return async (req, res, next) => {
    if (!req.user) return notLoggedIn(res);

    const resource = await load(req);
    const isOwner = resource && sameId(resource[ownerField], req.user.id);
    const isAllowedRole = allowRoles.includes(req.user.role);

    // Not found and "not yours" give the SAME answer on purpose.
    if (!resource || (!isOwner && !isAllowedRole)) {
      return res.status(404).json({ message: "Not found" });
    }

    req[resourceKey] = resource;
    next();
  };
}

// The logged-in user must be one of the PARTICIPANTS (for private conversations).
//   participantFields -> fields that hold the people in it, for example ["buyer", "seller"]
function requireParticipant({
  load,
  participantFields = ["buyer", "seller"],
  resourceKey = "resource",
}) {
  return async (req, res, next) => {
    if (!req.user) return notLoggedIn(res);

    const resource = await load(req);
    const isParticipant =
      resource &&
      participantFields.some((field) => sameId(resource[field], req.user.id));

    if (!isParticipant) {
      return res.status(404).json({ message: "Not found" });
    }

    req[resourceKey] = resource;
    next();
  };
}

// Blocks actions (like a new viewing request) on a suspended listing.
//   isSuspended(listing) -> decides what "suspended" means; the default handles
//   both a status of "suspended" and an isSuspended flag, because the listings
//   module is written by someone else.
function requireListingActive({
  load,
  isSuspended = (listing) =>
    listing.isSuspended === true || listing.status === "suspended",
  resourceKey = "listing",
}) {
  return async (req, res, next) => {
    const listing = await load(req);

    if (!listing) {
      return res.status(404).json({ message: "Not found" });
    }

    if (isSuspended(listing)) {
      return res
        .status(403)
        .json({ message: "This listing is not available for viewing requests" });
    }

    req[resourceKey] = listing;
    next();
  };
}

module.exports = {
  sameId,
  requireVerified,
  requireRole,
  requireOwner,
  requireParticipant,
  requireListingActive,
};