// api/events.js
if (!global.__gh_events) global.__gh_events = [];
const events = global.__gh_events;

module.exports = (req, res) => {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).send("Method Not Allowed");
  }
  // Simple auth: optional query token to avoid public dumping (NOT secure for prod)
  // Example: /api/events?token=devtoken
  const token = req.query.token;
  if (process.env.EVENTS_TOKEN && token !== process.env.EVENTS_TOKEN) {
    return res.status(401).send("Unauthorized");
  }

  res.status(200).json({
    count: events.length,
    events: events.slice(0, 50), // first 50 recent
  });
};
