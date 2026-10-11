// src/middleware/validate.js
// Checks req.body against a schema before the route's code runs.

function validate(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Validation failed",
        errors: result.error.issues.map((issue) => ({
          field: issue.path.join("."),
          message: issue.message,
        })),
      });
    }

    // Replace the body with the cleaned data (trimmed, lowercase email, etc.).
    req.body = result.data;
    next();
  };
}

module.exports = validate;